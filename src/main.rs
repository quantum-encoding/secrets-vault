//! secrets — Cross-platform encrypted secret manager
//!
//! Binary-compatible with the Zig version. Same QVLT vault format,
//! same crypto (AES-256-GCM + PBKDF2-SHA256 600k), same CLI interface.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::{env, fs, process};

use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"QVLT";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + TAG_LEN; // 49
const ITERATIONS: u32 = 600_000;
const MAX_KEY_LEN: usize = 256;
const MAX_VALUE_LEN: usize = 65536;

// ── CLI ──

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

// ── Vault binary format (matches Zig version exactly) ──
//
// Plaintext inside the ciphertext:
//   Repeated: [2 BE keylen][key bytes][4 BE vallen][value bytes]
//   Terminated by [0x00 0x00]

fn serialize_vault(entries: &BTreeMap<String, String>) -> Vec<u8> {
    let mut buf = Vec::new();
    for (key, value) in entries {
        let klen = key.len();
        buf.push((klen >> 8) as u8);
        buf.push((klen & 0xFF) as u8);
        buf.extend_from_slice(key.as_bytes());
        let vlen = value.len();
        buf.push((vlen >> 24) as u8);
        buf.push(((vlen >> 16) & 0xFF) as u8);
        buf.push(((vlen >> 8) & 0xFF) as u8);
        buf.push((vlen & 0xFF) as u8);
        buf.extend_from_slice(value.as_bytes());
    }
    buf.extend_from_slice(&[0x00, 0x00]); // terminator
    buf
}

fn deserialize_vault(data: &[u8]) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let klen = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;
        if klen == 0 {
            break;
        }
        if klen > MAX_KEY_LEN || pos + klen > data.len() {
            break;
        }
        let key = String::from_utf8_lossy(&data[pos..pos + klen]).to_string();
        pos += klen;
        if pos + 4 > data.len() {
            break;
        }
        let vlen = ((data[pos] as usize) << 24)
            | ((data[pos + 1] as usize) << 16)
            | ((data[pos + 2] as usize) << 8)
            | (data[pos + 3] as usize);
        pos += 4;
        if vlen > MAX_VALUE_LEN || pos + vlen > data.len() {
            break;
        }
        let value = String::from_utf8_lossy(&data[pos..pos + vlen]).to_string();
        pos += vlen;
        entries.insert(key, value);
    }
    entries
}

// ── Crypto ──

fn derive_key(passphrase: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(passphrase.as_bytes(), salt, ITERATIONS);
    *Key::<Aes256Gcm>::from_slice(&key)
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

// ── File I/O ──

fn vault_path() -> PathBuf {
    if let Ok(dir) = env::var("SECRETS_DIR") {
        return PathBuf::from(dir).join("vault.qvlt");
    }
    dirs::home_dir()
        .expect("HOME not set")
        .join(".config")
        .join("secrets")
        .join("vault.qvlt")
}

fn ensure_vault_dir(path: &PathBuf) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
        let mut perms = fs::metadata(parent)
            .map(|m| m.permissions())
            .unwrap_or_else(|_| fs::Permissions::from_mode(0o700));
        perms.set_mode(0o700);
        fs::set_permissions(parent, perms).ok();
    }
}

/// Load and decrypt the vault. Returns entries + passphrase (to reuse for save).
fn load_vault() -> (BTreeMap<String, String>, Zeroizing<String>) {
    let path = vault_path();
    let passphrase = get_passphrase();

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return (BTreeMap::new(), passphrase);
        }
        Err(e) => {
            eprintln!("Error reading vault: {e}");
            process::exit(1);
        }
    };

    if data.len() < HEADER_LEN {
        eprintln!("Vault file corrupt (too small)");
        process::exit(1);
    }
    if data[0..4] != MAGIC {
        eprintln!("Invalid vault file (bad magic)");
        process::exit(1);
    }
    if data[4] != VERSION {
        eprintln!("Unsupported vault version: {}", data[4]);
        process::exit(1);
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce_bytes = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let tag_bytes = &data[5 + SALT_LEN + NONCE_LEN..HEADER_LEN];
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(&passphrase, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    // AES-GCM decrypt in-place: ciphertext + tag
    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut buf, tag)
        .unwrap_or_else(|_| {
            eprintln!("Error: wrong passphrase");
            process::exit(1);
        });

    let entries = deserialize_vault(&buf);

    // Zero plaintext buffer
    buf.iter_mut().for_each(|b| *b = 0);

    (entries, passphrase)
}

/// Encrypt and write the vault. Reuses the passphrase from load_vault.
fn save_vault(entries: &BTreeMap<String, String>, passphrase: &str) {
    let path = vault_path();
    ensure_vault_dir(&path);

    let mut plaintext = serialize_vault(entries);

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(&key);

    // Encrypt in-place, get tag separately
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut plaintext)
        .expect("Encryption failed");

    // Write: magic + version + salt + nonce + tag + ciphertext
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

    file.write_all(&MAGIC).unwrap();
    file.write_all(&[VERSION]).unwrap();
    file.write_all(&salt).unwrap();
    file.write_all(nonce.as_slice()).unwrap();
    file.write_all(tag.as_slice()).unwrap();
    file.write_all(&plaintext).unwrap();
}

// ── Commands ──

fn cmd_set(key: &str, value: Option<String>) {
    if !is_valid_key(key) {
        eprintln!("Invalid key: '{key}' (use A-Z, 0-9, _)");
        process::exit(1);
    }

    let value = match value {
        Some(v) => v,
        None => {
            if atty::isnt(atty::Stream::Stdin) {
                // Piped stdin
                let mut buf = String::new();
                io::stdin().read_line(&mut buf).expect("Failed to read stdin");
                buf.trim_end_matches('\n').to_string()
            } else {
                prompt_password(format!("Enter value for {key}: ")).expect("Failed to read value")
            }
        }
    };

    if value.is_empty() {
        eprintln!("Error: empty value");
        process::exit(1);
    }

    let (mut entries, passphrase) = load_vault();
    entries.insert(key.to_string(), value);
    save_vault(&entries, &passphrase);
    eprintln!("Stored: {key}");
}

fn cmd_get(key: &str) {
    let (entries, _) = load_vault();
    match entries.get(key) {
        Some(value) => print!("{value}"),
        None => {
            eprintln!("Not found: {key}");
            process::exit(1);
        }
    }
}

fn cmd_delete(key: &str) {
    let (mut entries, passphrase) = load_vault();
    if entries.remove(key).is_some() {
        save_vault(&entries, &passphrase);
        eprintln!("Deleted: {key}");
    } else {
        eprintln!("Not found: {key}");
        process::exit(1);
    }
}

fn cmd_list() {
    let (entries, _) = load_vault();
    for key in entries.keys() {
        println!("{key}");
    }
}

fn cmd_env(json: bool) {
    let (entries, _) = load_vault();
    if json {
        // Pretty JSON
        println!("{{");
        let len = entries.len();
        for (i, (key, value)) in entries.iter().enumerate() {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            print!("  \"{key}\": \"{escaped}\"");
            if i + 1 < len {
                print!(",");
            }
            println!();
        }
        println!("}}");
    } else {
        for (key, value) in &entries {
            // Escape single quotes for safe shell eval
            let escaped = value.replace('\'', "'\\''");
            println!("export {key}='{escaped}'");
        }
    }
}

fn cmd_import() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read stdin");

    let (mut entries, passphrase) = load_vault();
    let mut count = 0usize;

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Strip "export " prefix
        let kv = trimmed.strip_prefix("export ").unwrap_or(trimmed);

        if let Some((key, value)) = kv.split_once('=') {
            let key = key.trim();
            // Strip surrounding quotes
            let value = value
                .trim()
                .trim_start_matches(|c| c == '"' || c == '\'')
                .trim_end_matches(|c| c == '"' || c == '\'');

            if is_valid_key(key) && !value.is_empty() {
                entries.insert(key.to_string(), value.to_string());
                count += 1;
            }
        }
    }

    save_vault(&entries, &passphrase);
    eprintln!("Imported {count} secrets");
}

fn cmd_export() {
    let (entries, _) = load_vault();
    for (key, value) in &entries {
        println!("{key}={value}");
    }
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Set { key, value } => cmd_set(&key, value),
        Commands::Get { key } => cmd_get(&key),
        Commands::Delete { key } => cmd_delete(&key),
        Commands::List => cmd_list(),
        Commands::Env { json } => cmd_env(json),
        Commands::Import => cmd_import(),
        Commands::Export => cmd_export(),
    }
}
