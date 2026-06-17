use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use std::{env, fs, process};

use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use zeroize::Zeroizing;

use secrets_vault::{is_valid_key, parse_env_lines, random_bytes, Vault, VaultError};

mod keychain;
mod registry;

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
        /// Namespace under a project (stored internally as project/KEY)
        #[arg(long, short)]
        project: Option<String>,
    },
    /// Generate a random secret and store it — value is NEVER printed
    Gen {
        /// Secret name
        key: String,
        /// Number of random bytes (hex-encoded; default 32 → 64 hex chars)
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        /// Overwrite if the key already exists
        #[arg(long)]
        force: bool,
        /// Namespace under a project (stored internally as project/KEY)
        #[arg(long, short)]
        project: Option<String>,
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
    List,
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
    Unlock,
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

/// Resolve the secret NAMES a project needs from `.secrets.toml` (current dir)
/// or the global `<secrets-dir>/projects.toml`. Supports both
/// `[projects.<name>] secrets = [...]` and a flat top-level `secrets = [...]`.
/// Names only ever leave the manifest — values stay in the encrypted vault.
fn resolve_project_secrets(project: &str) -> Result<Vec<String>, String> {
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
        .or_else(|| table.get("gsm").and_then(|g| g.get("secrets"))) // [gsm].secrets
        .or_else(|| table.get("secrets")) // flat top-level
        .ok_or_else(|| {
            format!("no secret list for '{project}' (expected [gsm].secrets, [projects.{project}].secrets, or a top-level secrets = [...])")
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
    Ok(names)
}

fn get_passphrase() -> Zeroizing<String> {
    if let Ok(pass) = env::var("SECRETS_PASSPHRASE") {
        return Zeroizing::new(pass);
    }
    // Biometric Keychain (Touch ID) — the unlocked path. None = not unlocked yet.
    match keychain::read("Unlock your secrets vault") {
        Ok(Some(p)) => return Zeroizing::new(p),
        Ok(None) => {}
        Err(e) => eprintln!("(keychain unavailable: {e})"),
    }
    prompt_only_passphrase()
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
        return;
    }

    #[cfg(not(unix))]
    {
        fs::write(&path, &encrypted).unwrap_or_else(|e| {
            eprintln!("Error writing vault: {e}");
            process::exit(1);
        });
    }
}

/// Validate key (+ project) and build the storage key: `project/KEY` or `KEY`.
fn scoped_key(project: &Option<String>, key: &str) -> String {
    if !is_valid_key(key) {
        eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _)");
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
        Commands::Set { key, value, project } => {
            let storage = scoped_key(&project, &key);
            let value = match value {
                Some(v) => v,
                None => {
                    if atty::isnt(atty::Stream::Stdin) {
                        let mut buf = String::new();
                        io::stdin().read_line(&mut buf).expect("Failed to read stdin");
                        buf.trim_end_matches('\n').to_string()
                    } else {
                        prompt_password(format!("Enter value for {key}: "))
                            .expect("Failed to read value")
                    }
                }
            };
            if value.is_empty() {
                eprintln!("Error: empty value");
                process::exit(1);
            }
            let (mut vault, passphrase) = load_vault();
            vault.set(storage.clone(), value);
            save_vault(&vault, &passphrase);
            eprintln!("Stored: {storage}");
        }

        Commands::Gen { key, bytes, force, project } => {
            let storage = scoped_key(&project, &key);
            if bytes == 0 || bytes > 1024 {
                eprintln!("Error: --bytes must be between 1 and 1024");
                process::exit(1);
            }
            let (mut vault, passphrase) = load_vault();
            if vault.get(&storage).is_some() && !force {
                eprintln!("'{storage}' already exists — use --force to regenerate (overwrites).");
                process::exit(1);
            }
            // Random bytes → hex → vault. The value is NEVER printed (no stdout,
            // no scrollback, no shell history): the agent only handles the name.
            let value = to_hex(&random_bytes(bytes));
            vault.set(storage.clone(), value);
            save_vault(&vault, &passphrase);
            eprintln!("Generated {storage} ({bytes} random bytes, hex) — value stored, never printed.");
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

        Commands::List => {
            let (vault, _) = load_vault();
            for key in vault.keys() {
                println!("{key}");
            }
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
            let (vault, _) = load_vault();
            for (key, value) in vault.iter() {
                println!("{key}={value}");
            }
        }

        Commands::Unlock => {
            let pass = prompt_only_passphrase();
            // If a vault already exists, verify the passphrase decrypts it before
            // storing — don't lock in a wrong passphrase.
            if let Ok(data) = fs::read(vault_path()) {
                if Vault::decrypt(&data, &pass).is_err() {
                    eprintln!("Wrong passphrase — nothing stored.");
                    process::exit(1);
                }
            }
            match keychain::store(&pass) {
                Ok(()) => eprintln!(
                    "Unlocked. Master key stored in the biometric Keychain — Touch ID required on read."
                ),
                Err(e) => {
                    eprintln!("Keychain store failed: {e}");
                    process::exit(1);
                }
            }
        }

        Commands::Lock => match keychain::delete() {
            Ok(()) => eprintln!("Locked. Biometric Keychain entry removed."),
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
            let names = resolve_project_secrets(&project).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });

            // One Touch ID: get the passphrase once, reuse for BOTH the registry
            // and the vault (no double prompt).
            let pass = get_passphrase();
            let dir = secrets_dir();
            let reg = registry::Registry::load(&dir, &pass).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });

            // Enforcement: a recognized agent must hold a valid grant — or earn one
            // via real-time approval in aiconductor (registry-anchored, NOT the
            // forgeable response file). A human / unrecognized operator who already
            // satisfied Touch ID proceeds.
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

            // Decrypt the vault (reuse pass — no second tap) and inject the
            // project-scoped values under their clean env-var names.
            let vault = load_vault_with(&pass);
            let mut cmd = process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            cmd.env_remove("SECRETS_PASSPHRASE");

            let mut injected = 0usize;
            let mut missing: Vec<&str> = Vec::new();
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
            eprintln!(
                "secrets exec: injecting {injected} secret(s) into `{}` (project: {project})",
                command[0]
            );

            let mut child = cmd.spawn().unwrap_or_else(|e| {
                eprintln!("Failed to spawn `{}`: {e}", command[0]);
                process::exit(127);
            });

            // The child holds its own env copy now — zeroize the vault plaintext
            // (and master key, already dropped) in OUR RAM immediately.
            drop(vault);

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
    }
}
