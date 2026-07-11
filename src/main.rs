use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs, process};

use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use zeroize::Zeroizing;

use secrets_vault::{is_valid_key, parse_env_lines, random_bytes, Vault, VaultError};

mod backend;
mod gsm;
mod inbox;
mod keychain;
mod registry;

use backend::Backend;

#[derive(Parser)]
#[command(name = "secrets", version = "1.0.0")]
#[command(about = "Encrypted secret manager — AES-256-GCM + PBKDF2")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Store a secret (prompts if no value given)
    Set {
        key: String,
        value: Option<String>,
        /// Read the value from stdin (explicit; a piped/redirected stdin is
        /// also auto-detected without this flag). Errors if a positional
        /// value is also given.
        #[arg(long, conflicts_with = "value")]
        stdin: bool,
        /// Namespace under a project (stored internally as project/KEY)
        #[arg(long, short)]
        project: Option<String>,
        /// Store in Google Secret Manager (requires --project = GCP project id)
        #[arg(long)]
        gsm: bool,
        /// Write to the external backend configured in .secrets.toml's [backend]
        /// block (AWS / Vault / Doppler / 1Password / …) instead of the local vault.
        #[arg(long)]
        remote: bool,
        /// Seal into the write-only inbox (no Touch ID) instead of the vault. Merge
        /// later with one tap (`secrets inbox merge`). Local-vault only.
        #[arg(long)]
        inbox: bool,
    },
    /// Generate a random secret and store it — value is NEVER printed
    Gen {
        /// Secret name
        key: String,
        /// Number of random bytes (hex-encoded; default 32 → 64 hex chars)
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        /// Overwrite if the key already exists (local only)
        #[arg(long)]
        force: bool,
        /// Namespace under a project (stored internally as project/KEY)
        #[arg(long, short)]
        project: Option<String>,
        /// Store in Google Secret Manager (requires --project = GCP project id)
        #[arg(long)]
        gsm: bool,
        /// Write to the external backend configured in .secrets.toml's [backend]
        /// block (AWS / Vault / Doppler / …) instead of the local vault.
        #[arg(long)]
        remote: bool,
        /// Seal into the write-only inbox (no Touch ID) instead of the vault. Merge
        /// later with one tap (`secrets inbox merge`). Local-vault only.
        #[arg(long)]
        inbox: bool,
    },
    /// Retrieve a secret (stdout, no trailing newline)
    Get {
        key: String,
        /// Namespace under a project (stored internally as project/KEY)
        #[arg(long, short)]
        project: Option<String>,
    },
    /// Remove a secret
    Delete { key: String },
    /// List all stored key names
    List {
        /// Read the plaintext name index (NO unlock / Touch ID) instead of the vault
        #[arg(long)]
        names_only: bool,
    },
    /// Check whether a key exists — names only, NO Touch ID, no value exposure.
    /// Prints `true`/`false`; exits 0 if present, 1 if not. Lets an agent avoid
    /// generating a duplicate secret without unlocking the vault.
    Has {
        key: String,
        /// Namespace under a project (checks project/KEY)
        #[arg(long, short)]
        project: Option<String>,
    },
    /// Output as shell exports or JSON
    Env {
        #[arg(long)]
        json: bool,
    },
    /// Import KEY=VALUE lines from stdin
    Import,
    /// Export all as KEY=VALUE
    Export,
    /// Store the vault passphrase in the biometric Keychain (Touch ID on read)
    Unlock {
        /// Strict mode: enrolled biometry ONLY (no watch/passcode fallback),
        /// self-invalidates on fingerprint change, and forces a FRESH tap on every
        /// read (no grace window). Trades convenience for max security.
        #[arg(long)]
        strict: bool,
    },
    /// Remove the biometric Keychain entry (re-lock)
    Lock,
    /// Run a command with ONLY a project's secrets in its environment.
    ///   secrets exec <project> -- <command> [args...]
    Exec {
        /// Project name — selects the secret list from .secrets.toml
        project: String,
        /// Command and arguments (everything after `--`)
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Authorize an agent to access a project (Touch ID gated)
    Authorize {
        agent: String,
        project: String,
        /// Timed session grant in minutes (default: permanent)
        #[arg(long)]
        session_minutes: Option<u64>,
    },
    /// Revoke an agent's access to a project (Touch ID gated)
    Revoke { agent: String, project: String },
    /// List registered projects and agent grants (Touch ID gated)
    ListProjects,
    /// Write-only inbox for agent-generated secrets (AGENT_SECRET_LIFECYCLE.md)
    Inbox {
        #[command(subcommand)]
        sub: InboxCmd,
    },
}

#[derive(Subcommand)]
enum InboxCmd {
    /// Generate the inbox keypair (identity → Keychain, recipient → inbox.pub).
    /// Idempotent and tap-free; also lazy-runs on the first `--inbox` write.
    Init,
    /// Show pending entries — names + new/⚠overwrite (from the name index). No Touch ID.
    List,
    /// Open + merge all pending entries into the vault — ONE Touch ID tap. Wipes the
    /// inbox; entries that fail to open stay behind. Overwrites are reported.
    Merge,
    /// Reject a pending entry by name (removes it without merging). No Touch ID.
    Drop { name: String },
}

fn vault_path() -> std::path::PathBuf {
    if let Ok(dir) = env::var("SECRETS_DIR") {
        return std::path::PathBuf::from(dir).join("vault.qvlt");
    }
    dirs::home_dir()
        .expect("HOME not set")
        .join(".config")
        .join("secrets")
        .join("vault.qvlt")
}

fn secrets_dir() -> PathBuf {
    if let Ok(dir) = env::var("SECRETS_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .expect("HOME not set")
        .join(".config")
        .join("secrets")
}

/// Load a project's manifest from `.secrets.toml` (current dir) or the global
/// `<secrets-dir>/projects.toml`: the secret NAMES it needs, plus which `Backend`
/// supplies the values. Name list comes from `[backend].secrets`, `[gsm].secrets`,
/// `[projects.<name>].secrets`, or a flat top-level `secrets = [...]`.
///
/// Backend selection (first match wins):
/// 1. `[backend]` table → `kind = "vault" | "gsm" | "command"` (see `backend::from_table`).
/// 2. `[gsm].project` → Google Secret Manager (backward-compatible shorthand).
/// 3. otherwise → the local biometric vault.
///
/// Only NAMES ever leave the manifest — values stay in the vault or the external manager.
fn load_manifest(project: &str) -> Result<(Vec<String>, Backend), String> {
    let candidates = [PathBuf::from(".secrets.toml"), secrets_dir().join("projects.toml")];
    let path = candidates.iter().find(|p| p.exists()).ok_or_else(|| {
        "no .secrets.toml in this directory (or projects.toml in your secrets dir)".to_string()
    })?;
    let content =
        fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let table: toml::Table = content
        .parse()
        .map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;

    let arr = table
        .get("projects")
        .and_then(|p| p.get(project))
        .and_then(|s| s.get("secrets"))
        .or_else(|| table.get("backend").and_then(|b| b.get("secrets"))) // [backend].secrets
        .or_else(|| table.get("gsm").and_then(|g| g.get("secrets"))) // [gsm].secrets
        .or_else(|| table.get("secrets")) // flat top-level
        .ok_or_else(|| {
            format!("no secret list for '{project}' (expected [backend].secrets, [gsm].secrets, [projects.{project}].secrets, or a top-level secrets = [...])")
        })?;
    let names: Vec<String> = arr
        .as_array()
        .ok_or_else(|| "`secrets` must be an array of names".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    if names.is_empty() {
        return Err(format!("project '{project}' lists no secrets"));
    }

    Ok((names, select_backend(&table)?))
}

/// Choose a `Backend` from a parsed manifest table (first match wins):
/// explicit `[backend]` → `[gsm].project` shorthand → local vault.
fn select_backend(table: &toml::Table) -> Result<Backend, String> {
    if let Some(bt) = table.get("backend").and_then(|b| b.as_table()) {
        backend::from_table(bt)
    } else if let Some(gcp) = table.get("gsm").and_then(|g| g.get("project")).and_then(|p| p.as_str()) {
        Ok(Backend::Gsm(gsm::GsmConfig {
            project: gcp.to_string(),
            account: table
                .get("gsm")
                .and_then(|g| g.get("account"))
                .and_then(|a| a.as_str())
                .map(String::from)
                .or_else(|| env::var("SECRETS_GSM_ACCOUNT").ok()),
            impersonate: table
                .get("gsm")
                .and_then(|g| g.get("impersonate"))
                .and_then(|a| a.as_str())
                .map(String::from)
                .or_else(|| env::var("SECRETS_GSM_IMPERSONATE").ok()),
        }))
    } else {
        Ok(Backend::Vault)
    }
}

/// Read just the backend from the manifest — for `set --remote` / `gen --remote`,
/// which write a value but don't need the project's secret-name list. Errors if no
/// manifest exists or it selects the local vault (there's nothing "remote" to write).
fn manifest_backend() -> Result<Backend, String> {
    let candidates = [PathBuf::from(".secrets.toml"), secrets_dir().join("projects.toml")];
    let path = candidates.iter().find(|p| p.exists()).ok_or_else(|| {
        "no .secrets.toml in this directory (or projects.toml in your secrets dir)".to_string()
    })?;
    let content =
        fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let table: toml::Table = content
        .parse()
        .map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;
    let be = select_backend(&table)?;
    if !be.is_external() {
        return Err("no external [backend] in .secrets.toml — nothing to write with --remote".into());
    }
    Ok(be)
}

/// Obtain the master passphrase: `SECRETS_PASSPHRASE` env → biometric Keychain read
/// (the native Touch ID sheet surfaces even from a headless/agent process and blocks
/// until the human taps — verified) → TTY prompt if we have a terminal → else fail
/// closed. Note: a single read here covers a whole `exec` batch (all keys decrypt in
/// one vault-open after this), so an exec does exactly ONE keychain read.
/// Marker file recording that the Keychain item was stored in strict mode, so
/// reads attach a zero-reuse LAContext. The item's own ACL (BiometryCurrentSet) is
/// the hard enforcement — this only controls the read-side reuse behavior.
fn strict_marker_path() -> PathBuf {
    secrets_dir().join("strict")
}

fn is_strict_mode() -> bool {
    strict_marker_path().exists()
}

fn get_passphrase() -> Zeroizing<String> {
    if let Ok(pass) = env::var("SECRETS_PASSPHRASE") {
        return Zeroizing::new(pass);
    }
    match keychain::read("Unlock your secrets vault", is_strict_mode()) {
        Ok(Some(p)) => return Zeroizing::new(p),
        Ok(None) => {} // no Keychain item yet (run `secrets unlock`)
        Err(e) => eprintln!("(keychain unavailable: {e})"),
    }
    if atty::is(atty::Stream::Stdin) {
        return prompt_only_passphrase();
    }
    // Headless and the vault isn't unlocked into the Keychain — fail closed.
    eprintln!("Vault is locked and there's no terminal to prompt on.");
    eprintln!("Run `secrets unlock` once (stores the master key behind Touch ID); after");
    eprintln!("that the Touch ID sheet surfaces even from a headless agent invocation.");
    process::exit(1);
}

/// Passphrase from env or a TTY prompt only — never the Keychain. Used by
/// `unlock` (which is *setting* the Keychain entry) to avoid a circular read.
fn prompt_only_passphrase() -> Zeroizing<String> {
    if let Ok(pass) = env::var("SECRETS_PASSPHRASE") {
        return Zeroizing::new(pass);
    }
    Zeroizing::new(prompt_password("Vault passphrase: ").unwrap_or_else(|e| {
        eprintln!("Error reading passphrase: {e}");
        process::exit(1);
    }))
}

/// Read a secret value from an interactive TTY, echoing a bullet (•) per
/// character so the typist sees the *length* accumulate — feedback the silent
/// rpassword prompt never gave. The value itself is never echoed. Handles
/// Backspace/Delete (erase one char), Enter (submit), Ctrl-C (abort 130),
/// Ctrl-D (submit what's typed). Falls back to the silent prompt when stdin
/// isn't a real terminal or raw mode can't be entered, so piped/redirected
/// callers are unaffected.
///
/// macOS-only raw path (libc is a macOS-target dep here for sysctl); other
/// platforms keep the silent prompt.
#[cfg(target_os = "macos")]
fn read_masked(prompt: &str) -> String {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    // Only drive raw mode on an interactive terminal; else defer to rpassword.
    if !atty::is(atty::Stream::Stdin) {
        return prompt_password(prompt).unwrap_or_default();
    }
    let fd = io::stdin().as_raw_fd();

    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return prompt_password(prompt).unwrap_or_default();
    }
    let mut raw = orig; // libc::termios is Copy — `orig` stays valid for restore
    raw.c_lflag &= !(libc::ICANON | libc::ECHO);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return prompt_password(prompt).unwrap_or_default();
    }

    // RAII: restore the terminal on every *normal* exit path (return / panic
    // unwind). Ctrl-C uses process::exit, which skips Drop, so that arm
    // restores explicitly before exiting.
    struct TermGuard {
        fd: libc::c_int,
        orig: libc::termios,
    }
    impl Drop for TermGuard {
        fn drop(&mut self) {
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
        }
    }
    let _guard = TermGuard { fd, orig };

    let mut err = io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();

    // Zeroizing so the plaintext buffer is wiped on drop.
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        if n <= 0 {
            break; // EOF / read error
        }
        match byte[0] {
            b'\n' | b'\r' => {
                let _ = write!(err, "\r\n");
                let _ = err.flush();
                break;
            }
            3 => {
                // Ctrl-C: restore the terminal ourselves (exit skips Drop), then abort.
                unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
                let _ = write!(err, "\r\n");
                let _ = err.flush();
                process::exit(130);
            }
            4 => break, // Ctrl-D: submit what's been typed so far
            0x7f | 0x08 => {
                // Backspace/Delete: drop one whole UTF-8 char, erase one bullet.
                if !buf.is_empty() {
                    while let Some(&b) = buf.last() {
                        buf.pop();
                        if (b & 0xC0) != 0x80 {
                            break; // stopped at the lead byte
                        }
                    }
                    let _ = write!(err, "\x08 \x08");
                    let _ = err.flush();
                }
            }
            b => {
                buf.push(b);
                // One bullet per character: skip UTF-8 continuation bytes.
                if (b & 0xC0) != 0x80 {
                    let _ = write!(err, "•");
                    let _ = err.flush();
                }
            }
        }
    }
    // `_guard` drops here → terminal restored.
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(not(target_os = "macos"))]
fn read_masked(prompt: &str) -> String {
    prompt_password(prompt).unwrap_or_default()
}

fn load_vault() -> (Vault, Zeroizing<String>) {
    let path = vault_path();
    let passphrase = get_passphrase();

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return (Vault::new(), passphrase);
        }
        Err(e) => {
            eprintln!("Error reading vault: {e}");
            process::exit(1);
        }
    };

    match Vault::decrypt(&data, &passphrase) {
        Ok(vault) => (vault, passphrase),
        Err(VaultError::DecryptionFailed) => {
            eprintln!("Error: wrong passphrase");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    }
}

fn save_vault(vault: &Vault, passphrase: &str) {
    let path = vault_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
        }
    }

    let encrypted = vault.encrypt(passphrase).unwrap_or_else(|e| {
        eprintln!("Error encrypting: {e}");
        process::exit(1);
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap_or_else(|e| {
                eprintln!("Error writing vault: {e}");
                process::exit(1);
            });
        io::Write::write_all(&mut file, &encrypted).unwrap();
        write_index(vault);
        return;
    }

    #[cfg(not(unix))]
    {
        fs::write(&path, &encrypted).unwrap_or_else(|e| {
            eprintln!("Error writing vault: {e}");
            process::exit(1);
        });
        write_index(vault);
    }
}

/// Plaintext index of vault KEY NAMES (never values) at `<secrets-dir>/index.json`,
/// refreshed on every vault save. Lets an agent answer "do we already have KEY?"
/// (`secrets has`) and enumerate names (`secrets list --names-only`) with NO Touch
/// ID and zero value exposure — names aren't secret (the manifest lists them too).
/// Newline-delimited, owner-only 0600. Best-effort: the encrypted vault stays the
/// source of truth; the index is only a no-unlock existence hint.
fn index_path() -> PathBuf {
    secrets_dir().join("index.json")
}

fn write_index(vault: &Vault) {
    let body = vault.keys().collect::<Vec<_>>().join("\n");
    let path = index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600).open(&path)
        {
            io::Write::write_all(&mut f, body.as_bytes()).ok();
        }
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, body.as_bytes()).ok();
    }
}

fn read_index() -> Vec<String> {
    fs::read_to_string(index_path())
        .map(|s| s.lines().filter(|l| !l.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

/// Validate key (+ project) and build the storage key: `project/KEY` or `KEY`.
fn scoped_key(project: &Option<String>, key: &str) -> String {
    if !is_valid_key(key) {
        eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _, -)");
        process::exit(1);
    }
    match project {
        Some(p) => {
            if !secrets_vault::is_valid_project(p) {
                eprintln!("Invalid project: '{p}' (use A-Z, 0-9, _, -, .)");
                process::exit(1);
            }
            format!("{p}/{key}")
        }
        None => key.to_string(),
    }
}

/// Build a GSM config for a GCP project, taking the acting account / impersonation
/// from the environment (override the active gcloud account if it lacks perms).
fn gsm_config(project: String) -> gsm::GsmConfig {
    gsm::GsmConfig {
        project,
        account: env::var("SECRETS_GSM_ACCOUNT").ok(),
        impersonate: env::var("SECRETS_GSM_IMPERSONATE").ok(),
    }
}

/// Decrypt the vault with an already-obtained passphrase — so callers that
/// already prompted Touch ID (e.g. `exec`, which also unlocked the registry)
/// don't trigger a SECOND biometric prompt.
fn load_vault_with(passphrase: &str) -> Vault {
    let path = vault_path();
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vault::new(),
        Err(e) => {
            eprintln!("Error reading vault: {e}");
            process::exit(1);
        }
    };
    match Vault::decrypt(&data, passphrase) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Error: wrong passphrase");
            process::exit(1);
        }
    }
}

/// Directory both `secrets` and `aiconductor` use for the approval handshake.
/// A plain same-user dir (no App Group entitlement / provisioning profile).
/// COORDINATION: aiconductor must watch this same path.
fn approval_dir() -> PathBuf {
    if let Ok(d) = env::var("SECRETS_APPROVAL_DIR") {
        return PathBuf::from(d);
    }
    dirs::home_dir()
        .expect("HOME not set")
        .join(".secrets")
        .join("pending_approvals")
}

/// Request real-time approval via aiconductor and return whether a valid grant
/// now exists. SECURITY: the `[id]_response.json` file is an UNTRUSTED "re-check"
/// signal — a same-user agent could forge it. The approval is real ONLY if a
/// grant now appears in the encrypted `registry.enc`, which only aiconductor (with
/// the human's biometric) can write. We re-read the registry with the passphrase
/// we already hold — no second CLI prompt.
fn ipc_approval(
    agent: &str,
    project: &str,
    command: &str,
    keys: &[String],
    reg_dir: &Path,
    passphrase: &str,
) -> bool {
    let dir = approval_dir();
    if fs::create_dir_all(&dir).is_err() {
        eprintln!("Could not create approval dir {}", dir.display());
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    let id = to_hex(&random_bytes(16));
    let req_path = dir.join(format!("{id}.json"));
    let resp_path = dir.join(format!("{id}_response.json"));

    let req = serde_json::json!({
        "id": id, "agent": agent, "project": project, "command": command, "keys": keys,
    });
    if fs::write(&req_path, serde_json::to_vec_pretty(&req).unwrap_or_default()).is_err() {
        eprintln!("Could not write approval request.");
        return false;
    }

    eprintln!("Waiting for approval in aiconductor… ({agent} → {project})");
    let timeout = env::var("SECRETS_APPROVAL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    let start = Instant::now();
    let granted = loop {
        if resp_path.exists() {
            // Untrusted signal → re-read the encrypted registry (the real boundary).
            let reg = registry::Registry::load(reg_dir, passphrase).unwrap_or_default();
            break reg.grant_for(agent, project, registry::now()).is_some();
        }
        if start.elapsed().as_secs() >= timeout {
            eprintln!("Approval timed out (is aiconductor running?).");
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let _ = fs::remove_file(&req_path);
    let _ = fs::remove_file(&resp_path);
    granted
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Loud stderr warning for the `secrets env` vault-dump footgun.
fn eval_warning() {
    let (red, bold, off) = if atty::is(atty::Stream::Stderr) {
        ("\x1b[1;31m", "\x1b[1m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    eprintln!("{red}⚠️  WARNING:{off} `secrets env` dumps your ENTIRE vault into the shell");
    eprintln!("   environment — every secret is then exposed to ALL child processes");
    eprintln!("   (including untrusted npm/pip postinstall scripts).");
    eprintln!("   Use {bold}secrets exec <project> -- <cmd>{off} for scoped, child-only injection.");
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Set { key, value, stdin, project, gsm, remote, inbox } => {
            if !is_valid_key(&key) {
                eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _, -)");
                process::exit(1);
            }
            let value = match value {
                Some(v) => v,
                None => {
                    // Explicit --stdin, or an auto-detected non-TTY stdin, reads
                    // the value from stdin (never argv). An interactive TTY gets
                    // the masked prompt (bullets show length; value never echoed).
                    if stdin || atty::isnt(atty::Stream::Stdin) {
                        // Read the ENTIRE payload to EOF. Multi-line values (e.g. a
                        // pretty-printed JSON service-account key) must NOT be
                        // truncated at the first newline — read_line did exactly
                        // that, storing only `{`. Strip a single trailing newline so
                        // the common `echo secret | secrets set` case stores `secret`
                        // (not `secret\n`); internal newlines are preserved verbatim.
                        let mut buf = String::new();
                        io::stdin().read_to_string(&mut buf).expect("Failed to read stdin");
                        let trimmed = buf.strip_suffix('\n').unwrap_or(&buf);
                        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
                        trimmed.to_string()
                    } else {
                        read_masked(&format!("Enter value for {key}: "))
                    }
                }
            };
            if value.is_empty() {
                eprintln!("Error: empty value");
                process::exit(1);
            }
            if inbox {
                if gsm || remote {
                    eprintln!("--inbox seals into the local vault inbox; not valid with --gsm/--remote.");
                    process::exit(1);
                }
                let storage = scoped_key(&project, &key);
                match inbox::append(&secrets_dir(), &storage, &value) {
                    Ok(count) => eprintln!(
                        "Sealed {storage} into the inbox ({count} pending) — no Touch ID. \
                         Merge later: secrets inbox merge"
                    ),
                    Err(e) => {
                        eprintln!("Inbox error: {e}");
                        process::exit(1);
                    }
                }
            } else if remote {
                let be = manifest_backend().unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    process::exit(1);
                });
                match be.add(&key, &value) {
                    Ok(()) => eprintln!("Stored {key} → {}.", be.label()),
                    Err(e) => {
                        eprintln!("{} error: {e}", be.label());
                        process::exit(1);
                    }
                }
            } else if gsm {
                let proj = project.unwrap_or_else(|| {
                    eprintln!("--gsm requires --project <gcp-project>");
                    process::exit(1);
                });
                let cfg = gsm_config(proj);
                match gsm::add(&cfg, &key, &value) {
                    Ok(()) => eprintln!("Stored {key} → GSM project '{}'.", cfg.project),
                    Err(e) => {
                        eprintln!("GSM error: {e}");
                        process::exit(1);
                    }
                }
            } else {
                let storage = scoped_key(&project, &key);
                let (mut vault, passphrase) = load_vault();
                vault.set(storage.clone(), value);
                save_vault(&vault, &passphrase);
                eprintln!("Stored: {storage}");
            }
        }

        Commands::Gen { key, bytes, force, project, gsm, remote, inbox } => {
            if !is_valid_key(&key) {
                eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _, -)");
                process::exit(1);
            }
            if bytes == 0 || bytes > 1024 {
                eprintln!("Error: --bytes must be between 1 and 1024");
                process::exit(1);
            }
            // Random bytes → hex. The value is NEVER printed (no stdout, no
            // scrollback, no shell history): the agent only handles the name.
            let value = to_hex(&random_bytes(bytes));
            if inbox {
                if gsm || remote {
                    eprintln!("--inbox seals into the local vault inbox; not valid with --gsm/--remote.");
                    process::exit(1);
                }
                // new-vs-overwrite is decided at merge against the unlocked vault, so
                // --force is irrelevant here; the inbox always accepts the seal.
                let _ = force;
                let storage = scoped_key(&project, &key);
                match inbox::append(&secrets_dir(), &storage, &value) {
                    Ok(count) => eprintln!(
                        "Generated {storage} ({bytes} bytes) → sealed into the inbox ({count} pending), \
                         value never printed. Merge later: secrets inbox merge"
                    ),
                    Err(e) => {
                        eprintln!("Inbox error: {e}");
                        process::exit(1);
                    }
                }
            } else if remote {
                let be = manifest_backend().unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    process::exit(1);
                });
                match be.add(&key, &value) {
                    Ok(()) => eprintln!(
                        "Generated {key} ({bytes} bytes) → {} — value never printed.",
                        be.label()
                    ),
                    Err(e) => {
                        eprintln!("{} error: {e}", be.label());
                        process::exit(1);
                    }
                }
            } else if gsm {
                let proj = project.unwrap_or_else(|| {
                    eprintln!("--gsm requires --project <gcp-project>");
                    process::exit(1);
                });
                let cfg = gsm_config(proj);
                match gsm::add(&cfg, &key, &value) {
                    Ok(()) => eprintln!(
                        "Generated {key} ({bytes} bytes) → GSM project '{}' — value never printed.",
                        cfg.project
                    ),
                    Err(e) => {
                        eprintln!("GSM error: {e}");
                        process::exit(1);
                    }
                }
            } else {
                let storage = scoped_key(&project, &key);
                let (mut vault, passphrase) = load_vault();
                if vault.get(&storage).is_some() && !force {
                    eprintln!("'{storage}' already exists — use --force to regenerate (overwrites).");
                    process::exit(1);
                }
                vault.set(storage.clone(), value);
                save_vault(&vault, &passphrase);
                eprintln!("Generated {storage} ({bytes} random bytes, hex) — value stored, never printed.");
            }
        }

        Commands::Get { key, project } => {
            let storage = scoped_key(&project, &key);
            let (vault, _) = load_vault();
            match vault.get(&storage) {
                Some(value) => print!("{value}"),
                None => {
                    eprintln!("Not found: {key}");
                    process::exit(1);
                }
            }
        }

        Commands::Delete { key } => {
            let (mut vault, passphrase) = load_vault();
            if vault.delete(&key).is_some() {
                save_vault(&vault, &passphrase);
                eprintln!("Deleted: {key}");
            } else {
                eprintln!("Not found: {key}");
                process::exit(1);
            }
        }

        Commands::List { names_only } => {
            if names_only {
                // No unlock: read the plaintext name index.
                for key in read_index() {
                    println!("{key}");
                }
            } else {
                let (vault, _) = load_vault();
                write_index(&vault); // self-heal the index while we hold the unlocked vault
                for key in vault.keys() {
                    println!("{key}");
                }
            }
        }

        Commands::Has { key, project } => {
            let storage = scoped_key(&project, &key);
            let exists = read_index().iter().any(|k| k == &storage);
            println!("{exists}");
            process::exit(if exists { 0 } else { 1 });
        }

        Commands::Env { json } => {
            // The `eval $(secrets env)` footgun — warn loudly (to stderr, so it
            // doesn't pollute the eval'd stdout). The shell-exports form is the one
            // people pipe into `eval`, so target that path.
            if !json {
                eval_warning();
            }
            let (vault, _) = load_vault();
            if json {
                print!("{}", vault.to_json());
            } else {
                print!("{}", vault.to_shell_exports());
            }
        }

        Commands::Import => {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .expect("Failed to read stdin");
            let (mut vault, passphrase) = load_vault();
            let pairs = parse_env_lines(&input);
            let count = pairs.len();
            for (key, value) in pairs {
                vault.set(key, value);
            }
            save_vault(&vault, &passphrase);
            eprintln!("Imported {count} secrets");
        }

        Commands::Export => {
            // The KEY=VALUE line format is newline-delimited, so it cannot faithfully
            // carry a value that itself contains newlines (a multi-line JSON key would
            // be split across physical lines and `import` — which parses line-by-line —
            // would only recover the first fragment). Rather than silently corrupt such
            // a value, warn loudly to stderr (stdout stays clean for redirection).
            let (vault, _) = load_vault();
            for (key, value) in vault.iter() {
                if value.contains('\n') {
                    eprintln!(
                        "warning: '{key}' is multi-line; the KEY=VALUE export format cannot \
                         round-trip it via `import`. Use `secrets get {key}` to retrieve it intact."
                    );
                }
                println!("{key}={value}");
            }
        }

        Commands::Unlock { strict } => {
            let pass = prompt_only_passphrase();
            // If a vault already exists, verify the passphrase decrypts it before
            // storing — don't lock in a wrong passphrase.
            if let Ok(data) = fs::read(vault_path()) {
                if Vault::decrypt(&data, &pass).is_err() {
                    eprintln!("Wrong passphrase — nothing stored.");
                    process::exit(1);
                }
            }
            match keychain::store(&pass, strict) {
                Ok(()) => {
                    // Persist (or clear) the strict marker so reads match the ACL.
                    let marker = strict_marker_path();
                    if strict {
                        if let Some(parent) = marker.parent() {
                            fs::create_dir_all(parent).ok();
                        }
                        let _ = fs::write(&marker, b"1");
                        eprintln!(
                            "Unlocked (STRICT). Enrolled biometry only, no reuse — a fresh Touch ID tap is required on every access."
                        );
                    } else {
                        let _ = fs::remove_file(&marker);
                        eprintln!(
                            "Unlocked. Master key stored in the biometric Keychain — Touch ID required on read (with the system reuse grace)."
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Keychain store failed: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Lock => match keychain::delete() {
            Ok(()) => {
                let _ = fs::remove_file(strict_marker_path());
                eprintln!("Locked. Biometric Keychain entry removed.");
            }
            Err(e) => {
                eprintln!("Keychain delete failed: {e}");
                process::exit(1);
            }
        },

        Commands::Exec { project, command } => {
            if command.is_empty() {
                eprintln!("Usage: secrets exec <project> -- <command> [args...]");
                process::exit(2);
            }
            if !secrets_vault::is_valid_project(&project) {
                eprintln!("Invalid project: '{project}'");
                process::exit(1);
            }
            let (names, be) = load_manifest(&project).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });

            // One Touch ID: get the passphrase once (native sheet surfaces even
            // headless), reuse for BOTH the registry and the whole-batch vault
            // decrypt — no second prompt.
            let pass = get_passphrase();
            let dir = secrets_dir();
            let reg = registry::Registry::load(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });

            // Enforcement: a recognized agent must hold a valid grant for this
            // project — or earn one via real-time approval in aiconductor (registry-
            // anchored, NOT the forgeable response file). The request it sends lists
            // the ENTIRE key batch, so the human reviews/authorizes all of it in one
            // consent. A human / unrecognized operator who satisfied Touch ID proceeds.
            if let Some(agent) = registry::resolve_agent() {
                if reg.grant_for(&agent, &project, registry::now()).is_none()
                    && !ipc_approval(&agent, &project, &command[0], &names, &dir, &pass)
                {
                    eprintln!("'{agent}' was not granted access to '{project}'.");
                    eprintln!("Or pre-authorize out-of-band:  secrets authorize {agent} {project}");
                    process::exit(1);
                }
                eprintln!("secrets exec: agent '{agent}' authorized for '{project}'.");
            }

            // Inject the project-scoped values under their clean env-var names.
            // Source is the configured Backend: the local biometric vault (reuse
            // `pass` — no second tap), or any external manager (GSM / AWS / Vault /
            // 1Password / Doppler / …) via its CLI. Values go ONLY into the child's
            // env, never argv.
            let mut cmd = process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            cmd.env_remove("SECRETS_PASSPHRASE");

            let mut injected = 0usize;
            let mut missing: Vec<&str> = Vec::new();
            match &be {
                Backend::Vault => {
                    let vault = load_vault_with(&pass);
                    for name in &names {
                        let skey = format!("{project}/{name}");
                        match vault.get(&skey) {
                            Some(value) => {
                                cmd.env(name, value); // ONLY into the child's env
                                injected += 1;
                            }
                            None => missing.push(name.as_str()),
                        }
                    }
                    if !missing.is_empty() {
                        eprintln!("warning: not in vault, skipped: {}", missing.join(", "));
                    }
                    // The child gets its own env copy on spawn; zeroize the vault
                    // plaintext in OUR RAM immediately after injection.
                    drop(vault);
                }
                external => {
                    eprintln!(
                        "secrets exec: pulling {} secret(s) from {}",
                        names.len(),
                        external.label()
                    );
                    for name in &names {
                        match external.access(name) {
                            // Value already has its trailing newline handled by the
                            // backend; goes ONLY into the child's env, never argv.
                            Ok(value) => {
                                cmd.env(name, value);
                                injected += 1;
                            }
                            Err(e) => {
                                eprintln!("  ! {name}: {e}");
                                missing.push(name.as_str());
                            }
                        }
                    }
                    if !missing.is_empty() {
                        eprintln!(
                            "warning: could not fetch from {}, skipped: {}",
                            external.label(),
                            missing.join(", ")
                        );
                    }
                }
            }
            eprintln!(
                "secrets exec: injecting {injected} secret(s) into `{}` (project: {project})",
                command[0]
            );

            let mut child = cmd.spawn().unwrap_or_else(|e| {
                eprintln!("Failed to spawn `{}`: {e}", command[0]);
                process::exit(127);
            });

            let status = child.wait().unwrap_or_else(|e| {
                eprintln!("Failed waiting for child: {e}");
                process::exit(1);
            });

            // Forward the child's exact exit code so CI/scripts see the real
            // result (signal → 128 + signo, matching shell convention).
            #[cfg(unix)]
            let code = {
                use std::os::unix::process::ExitStatusExt;
                status
                    .code()
                    .or_else(|| status.signal().map(|s| 128 + s))
                    .unwrap_or(1)
            };
            #[cfg(not(unix))]
            let code = status.code().unwrap_or(1);
            process::exit(code);
        }

        Commands::Authorize { agent, project, session_minutes } => {
            let pass = get_passphrase(); // Touch ID
            let dir = secrets_dir();
            let mut reg = registry::Registry::load(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });
            let scope = match session_minutes {
                Some(m) => registry::Scope::Session { expires: registry::now() + m * 60 },
                None => registry::Scope::Always,
            };
            reg.set_grant(&agent, &project, scope);
            reg.save(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });
            match session_minutes {
                Some(m) => eprintln!("Authorized '{agent}' → '{project}' for {m} min."),
                None => eprintln!("Authorized '{agent}' → '{project}' (permanent)."),
            }
        }

        Commands::Revoke { agent, project } => {
            let pass = get_passphrase();
            let dir = secrets_dir();
            let mut reg = registry::Registry::load(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });
            if reg.revoke(&agent, &project) {
                reg.save(&dir, &pass).unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    process::exit(1);
                });
                eprintln!("Revoked '{agent}' → '{project}'.");
            } else {
                eprintln!("No grant for '{agent}' → '{project}'.");
                process::exit(1);
            }
        }

        Commands::ListProjects => {
            let pass = get_passphrase();
            let dir = secrets_dir();
            let reg = registry::Registry::load(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });
            if reg.projects.is_empty() && reg.grants.is_empty() {
                println!("(registry empty — no projects or grants yet)");
            } else {
                let now = registry::now();
                if !reg.projects.is_empty() {
                    println!("Projects:");
                    for (name, meta) in &reg.projects {
                        println!("  {name} → {} ({} keys)", meta.gcp_project, meta.keys.len());
                    }
                }
                println!("Grants:");
                for (agent, projs) in &reg.grants {
                    for (project, grant) in projs {
                        let scope = match grant.scope {
                            registry::Scope::Always => "permanent".to_string(),
                            registry::Scope::Session { expires } if expires > now => {
                                format!("session, {}m left", (expires - now) / 60)
                            }
                            registry::Scope::Session { .. } => "expired".to_string(),
                        };
                        println!("  {agent} → {project} [{scope}]");
                    }
                }
            }
        }

        Commands::Inbox { sub } => {
            let dir = secrets_dir();
            match sub {
                InboxCmd::Init => match inbox::ensure_recipient(&dir) {
                    Ok(_) => eprintln!(
                        "Inbox ready — recipient at {} (identity in the Keychain).",
                        inbox::pub_path(&dir).display()
                    ),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        process::exit(1);
                    }
                },

                InboxCmd::List => {
                    let entries = inbox::read_entries(&dir).unwrap_or_default();
                    if entries.is_empty() {
                        eprintln!("Inbox empty — nothing pending.");
                    } else {
                        // new-vs-overwrite from the plaintext name index — no Touch ID.
                        let index = read_index();
                        eprintln!("{} pending (review, then `secrets inbox merge`):", entries.len());
                        for e in &entries {
                            let tag = if index.iter().any(|k| k == &e.name) {
                                "⚠ OVERWRITE"
                            } else {
                                "new"
                            };
                            println!("  {}  [{tag}]", e.name);
                        }
                    }
                }

                InboxCmd::Drop { name } => match inbox::drop_entry(&dir, &name) {
                    Ok(true) => eprintln!("Dropped pending '{name}'."),
                    Ok(false) => {
                        eprintln!("No pending entry named '{name}'.");
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        process::exit(1);
                    }
                },

                InboxCmd::Merge => {
                    let entries = match inbox::read_entries(&dir) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("Error: {e}");
                            process::exit(1);
                        }
                    };
                    if entries.is_empty() {
                        eprintln!("Inbox empty — nothing to merge.");
                        return;
                    }

                    // ONE tap (non-strict): open the inbox identity + the vault master
                    // under a single shared auth context. Strict mode → a fresh tap each.
                    let vals = match keychain::read_accounts(
                        &["inbox-identity", "vault-master"],
                        is_strict_mode(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("Keychain error: {e}");
                            process::exit(1);
                        }
                    };

                    let identity_str = match vals.first().cloned().flatten() {
                        Some(s) => s,
                        None => {
                            eprintln!("Inbox identity not found — run `secrets inbox init` first.");
                            process::exit(1);
                        }
                    };
                    let identity: age::x25519::Identity = match identity_str.parse() {
                        Ok(i) => i,
                        Err(e) => {
                            eprintln!("Corrupt inbox identity: {e}");
                            process::exit(1);
                        }
                    };

                    // Master: env override → the keychain read above.
                    let master = match env::var("SECRETS_PASSPHRASE")
                        .ok()
                        .or_else(|| vals.get(1).cloned().flatten())
                    {
                        Some(m) => Zeroizing::new(m),
                        None => {
                            eprintln!("Vault is locked — run `secrets unlock` first.");
                            process::exit(1);
                        }
                    };

                    let mut vault = load_vault_with(master.as_str());
                    let mut new_keys: Vec<String> = Vec::new();
                    let mut overwrites: Vec<String> = Vec::new();
                    let mut failed: Vec<(String, String)> = Vec::new();

                    for e in &entries {
                        match inbox::open(&identity, &e.sealed) {
                            Ok(value) => {
                                if vault.get(&e.name).is_some() {
                                    overwrites.push(e.name.clone());
                                } else {
                                    new_keys.push(e.name.clone());
                                }
                                vault.set(e.name.clone(), value);
                            }
                            Err(err) => failed.push((e.name.clone(), err)),
                        }
                    }

                    if new_keys.is_empty() && overwrites.is_empty() {
                        eprintln!("Nothing merged — all entries failed to open:");
                        for (n, err) in &failed {
                            eprintln!("  ✗ {n}: {err}");
                        }
                        process::exit(1);
                    }

                    save_vault(&vault, master.as_str()); // also refreshes the name index

                    // Keep only entries that failed to open; remove the merged ones.
                    use std::collections::HashSet;
                    let merged: HashSet<&String> =
                        new_keys.iter().chain(overwrites.iter()).collect();
                    let leftover: Vec<&inbox::Entry> =
                        entries.iter().filter(|e| !merged.contains(&e.name)).collect();
                    if let Err(e) = inbox::rewrite(&dir, &leftover) {
                        eprintln!("(warning: could not rewrite inbox: {e})");
                    }

                    eprintln!(
                        "Merged {} new + {} overwrite into the vault:",
                        new_keys.len(),
                        overwrites.len()
                    );
                    for n in &new_keys {
                        eprintln!("  + {n} (new)");
                    }
                    for n in &overwrites {
                        eprintln!("  ⚠ {n} (OVERWRITE)");
                    }
                    for (n, err) in &failed {
                        eprintln!("  ✗ {n}: {err} (left in inbox)");
                    }
                }
            }
        }
    }
}
