use std::io::{self, Read};
use std::{env, fs, process};

use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use zeroize::Zeroizing;

use secrets_vault::{is_valid_key, parse_env_lines, Vault, VaultError};

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

fn get_passphrase() -> Zeroizing<String> {
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
    }
}
