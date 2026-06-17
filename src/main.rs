use std::io::{self, Read};
use std::path::PathBuf;
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
    Set { key: String, value: Option<String> },
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
    },
    /// Retrieve a secret (stdout, no trailing newline)
    Get { key: String },
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
        .or_else(|| table.get("secrets"))
        .ok_or_else(|| {
            format!("no secret list for '{project}' (expected [projects.{project}].secrets or a top-level secrets = [...])")
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
        Commands::Set { key, value } => {
            if !is_valid_key(&key) {
                eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _)");
                process::exit(1);
            }
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
            vault.set(key.clone(), value);
            save_vault(&vault, &passphrase);
            eprintln!("Stored: {key}");
        }

        Commands::Gen { key, bytes, force } => {
            if !is_valid_key(&key) {
                eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _)");
                process::exit(1);
            }
            if bytes == 0 || bytes > 1024 {
                eprintln!("Error: --bytes must be between 1 and 1024");
                process::exit(1);
            }
            let (mut vault, passphrase) = load_vault();
            if vault.get(&key).is_some() && !force {
                eprintln!("'{key}' already exists — use --force to regenerate (overwrites).");
                process::exit(1);
            }
            // Random bytes → hex → vault. The value is NEVER printed (no stdout,
            // no scrollback, no shell history): the agent only handles the name.
            let value = to_hex(&random_bytes(bytes));
            vault.set(key.clone(), value);
            save_vault(&vault, &passphrase);
            eprintln!("Generated {key} ({bytes} random bytes, hex) — value stored, never printed.");
        }

        Commands::Get { key } => {
            let (vault, _) = load_vault();
            match vault.get(&key) {
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
            let names = resolve_project_secrets(&project).unwrap_or_else(|e| {
                eprintln!("Error: {e}");
                process::exit(1);
            });

            // One Touch ID prompt here (load_vault → keychain). The master
            // passphrase is dropped (zeroized) immediately via the `_`.
            let (vault, _) = load_vault();

            let mut cmd = process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            // Never let the child inherit the master key, whatever the parent env.
            cmd.env_remove("SECRETS_PASSPHRASE");

            let mut injected = 0usize;
            let mut missing: Vec<&str> = Vec::new();
            for name in &names {
                match vault.get(name) {
                    Some(value) => {
                        cmd.env(name, value); // injected into ONLY the child's env
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
