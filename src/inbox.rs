//! Write-only inbox — zero-interruption agent secret writes (AGENT_SECRET_LIFECYCLE.md).
//!
//! An agent seals a freshly-generated value to the inbox's **public** X25519 recipient
//! (no master key, no Touch ID) and appends it to `inbox.enc`. It can never read back
//! what it wrote: opening needs the **identity**, which lives in the biometric Keychain
//! and only surfaces after a tap at `inbox merge`. The inbox is a one-way drop box.
//!
//! Asymmetry is the whole security property: `seal` needs only `inbox.pub`; `open`
//! needs the Keychain identity. Names are plaintext (the manifest lists them anyway);
//! values are sealed. So `list` shows *what's pending* with no tap, values stay opaque
//! until merge.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use serde::{Deserialize, Serialize};

/// One pending inbox entry (`inbox.enc`, JSON-lines). Name plaintext, value sealed.
/// New-vs-overwrite is NOT stored here — it's computed at merge against the real vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub sealed: String, // age ASCII-armored ciphertext of the value
    pub issued: u64,    // unix seconds
}

pub fn pub_path(dir: &Path) -> PathBuf {
    dir.join("inbox.pub")
}
pub fn enc_path(dir: &Path) -> PathBuf {
    dir.join("inbox.enc")
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Pure crypto (no Keychain — unit-testable) ──

/// Seal a value to a recipient, ASCII-armored. Needs only the public recipient.
pub fn seal(recipient: &Recipient, value: &str) -> Result<String, String> {
    age::encrypt_and_armor(recipient, value.as_bytes()).map_err(|e| format!("seal failed: {e}"))
}

/// Open a sealed value with the identity. Needs the secret identity (Keychain at merge).
pub fn open(identity: &Identity, sealed: &str) -> Result<String, String> {
    let bytes = age::decrypt(identity, sealed.as_bytes()).map_err(|e| format!("open failed: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "decrypted value is not valid UTF-8".to_string())
}

// ── Keypair management (Keychain-backed) ──

/// Ensure the inbox keypair exists and return its public recipient. Idempotent and
/// **tap-free**: if `inbox.pub` exists and the Keychain holds the identity, reuse it;
/// otherwise generate a fresh pair, store the identity in the Keychain (storing needs
/// no tap — only reading does), and write the recipient to `inbox.pub` (0644, public).
pub fn ensure_recipient(dir: &Path) -> Result<Recipient, String> {
    let pubp = pub_path(dir);
    if pubp.exists() && crate::keychain::inbox_identity_exists() {
        let s = fs::read_to_string(&pubp).map_err(|e| format!("reading {}: {e}", pubp.display()))?;
        return s
            .trim()
            .parse::<Recipient>()
            .map_err(|e| format!("invalid inbox.pub: {e}"));
    }

    // Generate a fresh keypair. Identity → Keychain (UserPresence), recipient → disk.
    let identity = Identity::generate();
    let recipient = identity.to_public();
    crate::keychain::store_inbox_identity(identity.to_string().expose_secret())?;

    fs::create_dir_all(dir).ok();
    write_public(&pubp, &recipient.to_string())?;
    Ok(recipient)
}

#[cfg(unix)]
fn write_public(path: &Path, recipient: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644) // public key — world-readable is fine and intentional
        .open(path)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    f.write_all(recipient.as_bytes())
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_public(path: &Path, recipient: &str) -> Result<(), String> {
    fs::write(path, recipient.as_bytes()).map_err(|e| format!("writing {}: {e}", path.display()))
}

// ── Entry storage (`inbox.enc`, 0600, JSON-lines) ──

/// Seal `value` under `name` and append it. Tap-free. Returns the new pending count.
pub fn append(dir: &Path, name: &str, value: &str) -> Result<usize, String> {
    let recipient = ensure_recipient(dir)?;
    let sealed = seal(&recipient, value)?;
    let entry = Entry { name: name.to_string(), sealed, issued: now() };
    let line = serde_json::to_string(&entry).map_err(|e| format!("encoding entry: {e}"))?;

    let path = enc_path(dir);
    fs::create_dir_all(dir).ok();
    append_line(&path, &line)?;
    Ok(read_entries(dir).map(|e| e.len()).unwrap_or(0))
}

#[cfg(unix)]
fn append_line(path: &Path, line: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn append_line(path: &Path, line: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("writing {}: {e}", path.display()))
}

/// All pending entries (values still sealed). Tap-free. Skips malformed lines.
pub fn read_entries(dir: &Path) -> Result<Vec<Entry>, String> {
    let path = enc_path(dir);
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    Ok(content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect())
}

/// Remove one pending entry by name (reject). Returns whether it was present.
/// Rewrites `inbox.enc` without the named entry, preserving order. Tap-free.
pub fn drop_entry(dir: &Path, name: &str) -> Result<bool, String> {
    let entries = read_entries(dir)?;
    let kept: Vec<&Entry> = entries.iter().filter(|e| e.name != name).collect();
    if kept.len() == entries.len() {
        return Ok(false);
    }
    rewrite(dir, &kept)?;
    Ok(true)
}

/// Replace the inbox file with `entries` (used by drop / partial merge). Tap-free.
pub fn rewrite(dir: &Path, entries: &[&Entry]) -> Result<(), String> {
    let path = enc_path(dir);
    if entries.is_empty() {
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let body: String = entries
        .iter()
        .filter_map(|e| serde_json::to_string(e).ok())
        .collect::<Vec<_>>()
        .join("\n");
    write_private(&path, &body)
}

#[cfg(unix)]
fn write_private(path: &Path, body: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    writeln!(f, "{body}").map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body.as_bytes()).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        // Pure crypto path — no Keychain. Proves the age armor API + asymmetry.
        let identity = Identity::generate();
        let recipient = identity.to_public();

        let sealed = seal(&recipient, "sk-cloudflare-secret-123").unwrap();
        assert!(sealed.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

        let opened = open(&identity, &sealed).unwrap();
        assert_eq!(opened, "sk-cloudflare-secret-123");
    }

    #[test]
    fn wrong_identity_cannot_open() {
        let recipient = Identity::generate().to_public();
        let attacker = Identity::generate(); // a different identity (e.g. the agent's)
        let sealed = seal(&recipient, "secret").unwrap();
        assert!(open(&attacker, &sealed).is_err(), "write-only: only the inbox identity opens");
    }

    #[test]
    fn entries_round_trip_json() {
        let e = Entry { name: "CLOUDFLARE_TOKEN".into(), sealed: "x".into(), issued: 1750000000 };
        let line = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&line).unwrap();
        assert_eq!(back.name, "CLOUDFLARE_TOKEN");
        assert_eq!(back.issued, 1750000000);
    }
}
