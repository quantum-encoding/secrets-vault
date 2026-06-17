//! # secrets-vault
//!
//! AES-256-GCM encrypted key-value vault with PBKDF2-SHA256 key derivation.
//! Binary-compatible with the [Zig version](https://github.com/quantum-encoding/quantum-zig-forge).
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use secrets_vault::Vault;
//!
//! // Create or load a vault
//! let mut vault = Vault::new();
//! vault.set("API_KEY", "sk-secret-123");
//! vault.set("DB_URL", "postgres://localhost/mydb");
//!
//! // Encrypt and save
//! let bytes = vault.encrypt("my-passphrase")?;
//! std::fs::write("vault.qvlt", &bytes)?;
//!
//! // Load and decrypt
//! let data = std::fs::read("vault.qvlt")?;
//! let vault = Vault::decrypt(&data, "my-passphrase")?;
//! assert_eq!(vault.get("API_KEY"), Some("sk-secret-123"));
//! # Ok::<(), secrets_vault::VaultError>(())
//! ```
//!
//! ## Vault File Format (QVLT)
//!
//! ```text
//! [4 bytes]  Magic:     "QVLT"
//! [1 byte]   Version:   0x01
//! [16 bytes] PBKDF2 salt (random per save)
//! [12 bytes] AES-GCM nonce (random per save)
//! [16 bytes] AES-GCM authentication tag
//! [N bytes]  Ciphertext (encrypted key-value pairs)
//! ```
//!
//! ## Security
//!
//! - AES-256-GCM authenticated encryption (NIST)
//! - PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023)
//! - Fresh random salt + nonce on every encrypt
//! - Plaintext zeroed after use
//! - Tamper detection via GCM authentication tag

use std::collections::BTreeMap;
use std::io::Write;

use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use zeroize::Zeroize;

// ── Constants ──

const MAGIC: [u8; 4] = *b"QVLT";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + TAG_LEN; // 49

/// PBKDF2 iteration count (OWASP 2023 recommendation for SHA-256).
pub const ITERATIONS: u32 = 600_000;

/// Maximum key name length in bytes.
pub const MAX_KEY_LEN: usize = 256;

/// Maximum value length in bytes.
pub const MAX_VALUE_LEN: usize = 65536;

// ── Errors ──

/// Errors that can occur during vault operations.
#[derive(Debug)]
pub enum VaultError {
    /// Vault file is too small to contain a valid header.
    TooSmall,
    /// Magic bytes don't match "QVLT".
    BadMagic,
    /// Vault version is not supported.
    UnsupportedVersion(u8),
    /// AES-GCM decryption failed — wrong passphrase or tampered data.
    DecryptionFailed,
    /// AES-GCM encryption failed.
    EncryptionFailed,
    /// Vault data is malformed.
    MalformedData,
    /// I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall => write!(f, "vault file too small"),
            Self::BadMagic => write!(f, "invalid vault file (bad magic)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported vault version: {v}"),
            Self::DecryptionFailed => write!(f, "decryption failed (wrong passphrase?)"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::MalformedData => write!(f, "malformed vault data"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Vault ──

/// An in-memory key-value store that can be encrypted to/from the QVLT format.
///
/// Keys are stored sorted (BTreeMap) for deterministic output.
/// Values are zeroed from memory when the vault is dropped.
#[derive(Debug, Clone)]
pub struct Vault {
    entries: BTreeMap<String, String>,
}

impl Vault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Create a vault from an existing map.
    pub fn from_map(entries: BTreeMap<String, String>) -> Self {
        Self { entries }
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Set a key-value pair. Returns the previous value if the key existed.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.entries.insert(key.into(), value.into())
    }

    /// Remove a key. Returns the value if it existed.
    pub fn delete(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    /// List all key names (sorted).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    /// Iterate over all key-value pairs (sorted by key).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a mutable reference to the underlying map.
    pub fn entries_mut(&mut self) -> &mut BTreeMap<String, String> {
        &mut self.entries
    }

    /// Clone the underlying map. (Cannot move due to Drop impl that zeroes memory.)
    pub fn to_map(&self) -> BTreeMap<String, String> {
        self.entries.clone()
    }

    // ── Encryption / Decryption ──

    /// Encrypt the vault into QVLT binary format.
    ///
    /// Uses a fresh random salt and nonce each time, so calling this twice
    /// with the same data produces different ciphertext.
    pub fn encrypt(&self, passphrase: &str) -> Result<Vec<u8>, VaultError> {
        let mut plaintext = serialize(&self.entries);

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let key = derive_key(passphrase, &salt);
        let cipher = Aes256Gcm::new(&key);

        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut plaintext)
            .map_err(|_| VaultError::EncryptionFailed)?;

        // Zero the derived key (it's on the stack, but let's be explicit)
        drop(cipher);

        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len());
        out.write_all(&MAGIC)?;
        out.write_all(&[VERSION])?;
        out.write_all(&salt)?;
        out.write_all(nonce.as_slice())?;
        out.write_all(tag.as_slice())?;
        out.write_all(&plaintext)?;

        Ok(out)
    }

    /// Decrypt a QVLT binary blob into a vault.
    ///
    /// Returns `VaultError::DecryptionFailed` if the passphrase is wrong
    /// or the data has been tampered with.
    pub fn decrypt(data: &[u8], passphrase: &str) -> Result<Self, VaultError> {
        if data.len() < HEADER_LEN {
            return Err(VaultError::TooSmall);
        }
        if data[0..4] != MAGIC {
            return Err(VaultError::BadMagic);
        }
        if data[4] != VERSION {
            return Err(VaultError::UnsupportedVersion(data[4]));
        }

        let salt = &data[5..5 + SALT_LEN];
        let nonce_bytes = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
        let tag_bytes = &data[5 + SALT_LEN + NONCE_LEN..HEADER_LEN];
        let ciphertext = &data[HEADER_LEN..];

        let key = derive_key(passphrase, salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);
        let tag = Tag::from_slice(tag_bytes);

        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, b"", &mut buf, tag)
            .map_err(|_| VaultError::DecryptionFailed)?;

        let entries = deserialize(&buf);

        // Zero plaintext
        buf.zeroize();

        Ok(Self { entries })
    }

    // ── Shell output helpers ──

    /// Format all entries as `export KEY='VALUE'` lines for shell eval.
    ///
    /// Single quotes in values are escaped as `'\''`.
    pub fn to_shell_exports(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.entries {
            let escaped = value.replace('\'', "'\\''");
            out.push_str(&format!("export {key}='{escaped}'\n"));
        }
        out
    }

    /// Format all entries as a JSON object.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\n");
        let len = self.entries.len();
        for (i, (key, value)) in self.entries.iter().enumerate() {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("  \"{key}\": \"{escaped}\""));
            if i + 1 < len {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("}\n");
        out
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Zero all values in memory
        for value in self.entries.values_mut() {
            unsafe {
                let bytes = value.as_bytes_mut();
                bytes.zeroize();
            }
        }
    }
}

// ── Key validation ──

/// Check if a key name is valid (alphanumeric + underscore, non-empty, ≤256 bytes).
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse KEY=VALUE lines (with optional `export` prefix and quote stripping).
///
/// Useful for importing from `.env` files or shell config exports.
pub fn parse_env_lines(input: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let kv = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((key, value)) = kv.split_once('=') {
            let key = key.trim();
            let value = value
                .trim()
                .trim_start_matches(|c| c == '"' || c == '\'')
                .trim_end_matches(|c| c == '"' || c == '\'');
            if is_valid_key(key) && !value.is_empty() {
                pairs.push((key.to_string(), value.to_string()));
            }
        }
    }
    pairs
}

/// Generate `n` cryptographically secure random bytes from the OS CSPRNG.
/// Used by `secrets gen` so a fresh credential never has to be printed.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Encrypt arbitrary bytes into the same QVLT container the vault uses (AES-256-GCM,
/// PBKDF2-SHA256 @ 600k, fresh salt+nonce). Lets other on-disk artifacts (e.g. the
/// scoped registry) reuse the audited crypto core without touching `Vault`.
pub fn encrypt_blob(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, VaultError> {
    let mut buf = plaintext.to_vec();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new(&key);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, b"", &mut buf)
        .map_err(|_| VaultError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(HEADER_LEN + buf.len());
    out.write_all(&MAGIC)?;
    out.write_all(&[VERSION])?;
    out.write_all(&salt)?;
    out.write_all(nonce.as_slice())?;
    out.write_all(tag.as_slice())?;
    out.write_all(&buf)?;
    buf.zeroize();
    Ok(out)
}

/// Decrypt a QVLT container produced by [`encrypt_blob`]. Returns the plaintext
/// bytes (caller zeroizes after use).
pub fn decrypt_blob(data: &[u8], passphrase: &str) -> Result<Vec<u8>, VaultError> {
    if data.len() < HEADER_LEN {
        return Err(VaultError::TooSmall);
    }
    if data[0..4] != MAGIC {
        return Err(VaultError::BadMagic);
    }
    if data[4] != VERSION {
        return Err(VaultError::UnsupportedVersion(data[4]));
    }
    let salt = &data[5..5 + SALT_LEN];
    let nonce_bytes = &data[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
    let tag_bytes = &data[5 + SALT_LEN + NONCE_LEN..HEADER_LEN];
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut buf, tag)
        .map_err(|_| VaultError::DecryptionFailed)?;
    Ok(buf)
}

// ── Internal: Binary serialization (QVLT format) ──

fn serialize(entries: &BTreeMap<String, String>) -> Vec<u8> {
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
    buf.extend_from_slice(&[0x00, 0x00]);
    buf
}

fn deserialize(data: &[u8]) -> BTreeMap<String, String> {
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

// ── Internal: Crypto ──

fn derive_key(passphrase: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let key =
        pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(passphrase.as_bytes(), salt, ITERATIONS);
    *Key::<Aes256Gcm>::from_slice(&key)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut vault = Vault::new();
        vault.set("API_KEY", "sk-secret-123");
        vault.set("DB_URL", "postgres://localhost/mydb");

        let encrypted = vault.encrypt("test-pass").unwrap();
        let decrypted = Vault::decrypt(&encrypted, "test-pass").unwrap();

        assert_eq!(decrypted.get("API_KEY"), Some("sk-secret-123"));
        assert_eq!(decrypted.get("DB_URL"), Some("postgres://localhost/mydb"));
        assert_eq!(decrypted.len(), 2);
    }

    #[test]
    fn wrong_passphrase() {
        let vault = Vault::new();
        let encrypted = vault.encrypt("correct").unwrap();
        assert!(matches!(
            Vault::decrypt(&encrypted, "wrong"),
            Err(VaultError::DecryptionFailed)
        ));
    }

    #[test]
    fn tamper_detection() {
        let mut vault = Vault::new();
        vault.set("KEY", "value");
        let mut encrypted = vault.encrypt("pass").unwrap();
        // Flip a byte in the ciphertext
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }
        assert!(Vault::decrypt(&encrypted, "pass").is_err());
    }

    #[test]
    fn fresh_nonce_per_encrypt() {
        let vault = Vault::new();
        let a = vault.encrypt("pass").unwrap();
        let b = vault.encrypt("pass").unwrap();
        // Same data, different ciphertext (different salt + nonce)
        assert_ne!(a, b);
    }

    #[test]
    fn shell_escaping() {
        let mut vault = Vault::new();
        vault.set("KEY", "it's a \"test\"");
        let exports = vault.to_shell_exports();
        assert!(exports.contains("'it'\\''s a \"test\"'"));
    }

    #[test]
    fn valid_keys() {
        assert!(is_valid_key("API_KEY"));
        assert!(is_valid_key("key123"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("has space"));
        assert!(!is_valid_key("has-dash"));
    }

    #[test]
    fn parse_env() {
        let input = r#"
export API_KEY="sk-123"
DB_URL=postgres://localhost
# comment
export EMPTY=

BARE=value
"#;
        let pairs = parse_env_lines(input);
        assert_eq!(pairs.len(), 3);
        // parse_env_lines returns in file order, not sorted
        assert_eq!(pairs[0], ("API_KEY".into(), "sk-123".into()));
        assert_eq!(pairs[1], ("DB_URL".into(), "postgres://localhost".into()));
        assert_eq!(pairs[2], ("BARE".into(), "value".into()));
    }
}
