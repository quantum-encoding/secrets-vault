//! Session-unlock broker (ssh-agent model). ONE Touch ID starts a short-lived
//! daemon that holds the decrypted vault passphrase in memory and hands it to
//! same-user `secrets exec` callers over a Unix socket — so an unattended drain
//! (many agent launches over minutes) taps once, not once per launch, and the
//! passphrase NEVER lands in a child env (unlike SECRETS_PASSPHRASE).
//!
//! Security boundary: the socket lives at `~/.secrets/session.sock` with 0600
//! perms inside the 0700 secrets dir — only the owning uid can connect (the
//! same FS-level guarantee ssh-agent relies on). The passphrase is held in
//! `Zeroizing` memory, never written to disk, and the daemon self-terminates
//! after the requested lifetime. The passphrase reaches the daemon over a pipe
//! (child stdin), never argv (ps) or env.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Socket path — inside the (0700) secrets dir so only the owner can reach it.
pub fn socket_path(secrets_dir: &std::path::Path) -> PathBuf {
    secrets_dir.join("session.sock")
}

/// CLIENT: try the running session broker. Returns the passphrase if a live
/// broker answers, else None (caller falls back to the Touch ID Keychain read).
/// Any error is a silent None — a missing/expired broker is the normal case.
pub fn request_passphrase(secrets_dir: &std::path::Path) -> Option<Zeroizing<String>> {
    let path = socket_path(secrets_dir);
    let mut stream = UnixStream::connect(&path).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.write_all(b"GET\n").ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    let pass = buf.strip_suffix('\n').unwrap_or(&buf).to_string();
    if pass.is_empty() {
        None
    } else {
        Some(Zeroizing::new(pass))
    }
}

/// CLIENT: ask a running broker to shut down NOW (used by `secrets lock`).
/// Best-effort; also unlinks the socket so a wedged daemon can't be reached.
pub fn end(secrets_dir: &std::path::Path) {
    let path = socket_path(secrets_dir);
    if let Ok(mut s) = UnixStream::connect(&path) {
        let _ = s.write_all(b"END\n");
    }
    let _ = std::fs::remove_file(&path);
}

/// DAEMON: serve the passphrase to same-user callers until the lifetime expires
/// or an `END` arrives. Called ONLY by the hidden `__session-serve` subcommand
/// in the detached child; `pass` was read from the child's stdin (pipe), never
/// argv/env. Blocks until exit, then removes the socket.
pub fn serve(secrets_dir: &std::path::Path, minutes: u64, pass: Zeroizing<String>) -> Result<(), String> {
    let path = socket_path(secrets_dir);
    // Fresh socket: unlink a stale one first (a prior daemon that died hard).
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    // 0600 BEFORE we accept anything — owner-only is the whole security model.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod socket: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(minutes.saturating_mul(60));
    // Non-blocking accept + short poll so the deadline is honored even with no
    // callers, and an `END` shuts us down promptly.
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;

    loop {
        if Instant::now() >= deadline {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // The accepted stream can inherit the listener's non-blocking
                // flag — force blocking + a short read timeout so a request is
                // read whole and a silent client can't wedge the loop.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut req = [0u8; 8];
                let n = stream.read(&mut req).unwrap_or(0);
                let cmd = &req[..n];
                if cmd.starts_with(b"END") {
                    break;
                }
                if cmd.starts_with(b"GET") {
                    let mut line = Vec::with_capacity(pass.len() + 1);
                    line.extend_from_slice(pass.as_bytes());
                    line.push(b'\n');
                    let _ = stream.write_all(&line);
                    // line holds a copy of the secret — scrub it.
                    for b in line.iter_mut() {
                        *b = 0;
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Detach from the controlling terminal so the broker outlives the shell that
/// started it (the drain may run long after the launching command returns).
/// `setsid` makes us a new session leader with no controlling tty.
pub fn detach() {
    unsafe {
        libc::setsid();
    }
}
