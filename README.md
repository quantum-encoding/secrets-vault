# secrets-vault

[![Crates.io](https://img.shields.io/crates/v/secrets-vault.svg)](https://crates.io/crates/secrets-vault)
[![Docs.rs](https://docs.rs/secrets-vault/badge.svg)](https://docs.rs/secrets-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

AES-256-GCM encrypted key-value vault with PBKDF2 key derivation. Store API keys, tokens, and credentials in a single encrypted file instead of plaintext dotfiles.

Works as a **Rust library** (4 dependencies) and a **CLI tool** (508 KB binary).

## The Problem

```bash
# Your .zshrc right now:
export ANTHROPIC_API_KEY="sk-ant-api03-..."
export STRIPE_SECRET_KEY="sk_live_..."
export OPENAI_API_KEY="sk-proj-..."
```

Any tool, script, or AI agent that reads your shell config gets every key.

## The Solution

```bash
# Your .zshrc after:
eval $(secrets env 2>/dev/null)
```

One line. Zero plaintext keys. Secrets are decrypted from an AES-256-GCM vault at shell startup.

## Install

### CLI binary

```bash
cargo install secrets-vault
```

### As a library

```toml
[dependencies]
secrets-vault = { version = "1", default-features = false }
```

## CLI Quick Start

```bash
# Store secrets
secrets set ANTHROPIC_API_KEY "sk-ant-api03-..."
secrets set STRIPE_SECRET_KEY "sk_live_..."

# Add to shell config
echo 'eval $(secrets env 2>/dev/null)' >> ~/.zshrc

# Done. New shells load secrets from the encrypted vault.
```

### Commands

```
secrets set KEY [VALUE]   Store a secret (prompts with hidden input if no value)
secrets get KEY           Retrieve a secret (stdout, no trailing newline)
secrets delete KEY        Remove a secret
secrets list              List all key names (sorted)
secrets env               Output all as export KEY='VALUE' for eval
secrets env --json        Output as JSON object
secrets import            Import KEY=VALUE lines from stdin
secrets export            Export all as KEY=VALUE
secrets --version         Show version
```

### Bulk import from existing shell config

```bash
grep "^export" ~/.zshrc | secrets import
# Then remove the plaintext exports and add:
# eval $(secrets env 2>/dev/null)
```

### Passphrase

The vault passphrase can be provided three ways:

1. **`SECRETS_PASSPHRASE` env var** — for scripts, CI, shell init
2. **Interactive prompt** — hidden input, used by default
3. **macOS Keychain** — store the passphrase in Keychain for auto-unlock:
   ```bash
   security add-generic-password -s "secrets-vault-passphrase" -a "$(whoami)" -w "your-passphrase" -U
   # Then in .zshrc:
   eval $(SECRETS_PASSPHRASE="$(security find-generic-password -s secrets-vault-passphrase -w 2>/dev/null)" secrets env 2>/dev/null)
   ```

## Library Usage

```rust
use secrets_vault::Vault;

// Create a vault and add secrets
let mut vault = Vault::new();
vault.set("API_KEY", "sk-secret-123");
vault.set("DB_URL", "postgres://localhost/mydb");

// Encrypt to bytes (QVLT format)
let encrypted = vault.encrypt("my-passphrase")?;
std::fs::write("vault.qvlt", &encrypted)?;

// Decrypt from bytes
let data = std::fs::read("vault.qvlt")?;
let vault = Vault::decrypt(&data, "my-passphrase")?;

assert_eq!(vault.get("API_KEY"), Some("sk-secret-123"));
assert_eq!(vault.get("DB_URL"), Some("postgres://localhost/mydb"));
```

### API

```rust
// Core
Vault::new() -> Vault
Vault::from_map(BTreeMap<String, String>) -> Vault
vault.set(key, value) -> Option<String>      // returns previous value
vault.get(key) -> Option<&str>
vault.delete(key) -> Option<String>
vault.keys() -> impl Iterator<Item = &str>   // sorted
vault.iter() -> impl Iterator<Item = (&str, &str)>
vault.len() -> usize
vault.is_empty() -> bool

// Crypto
vault.encrypt(passphrase) -> Result<Vec<u8>, VaultError>
Vault::decrypt(data, passphrase) -> Result<Vault, VaultError>

// Output
vault.to_shell_exports() -> String    // export KEY='VALUE'\n...
vault.to_json() -> String             // { "KEY": "VALUE", ... }

// Helpers
is_valid_key(key) -> bool                            // A-Z, 0-9, _
parse_env_lines(text) -> Vec<(String, String)>       // parse KEY=VALUE lines
```

### Error Handling

```rust
use secrets_vault::{Vault, VaultError};

match Vault::decrypt(&data, passphrase) {
    Ok(vault) => { /* use vault */ }
    Err(VaultError::DecryptionFailed) => eprintln!("Wrong passphrase"),
    Err(VaultError::BadMagic) => eprintln!("Not a vault file"),
    Err(VaultError::TooSmall) => eprintln!("File is corrupt"),
    Err(e) => eprintln!("Error: {e}"),
}
```

### Embedding in a Tauri / Desktop App

```rust
use secrets_vault::Vault;

// Load user's vault at app startup
fn load_user_secrets(passphrase: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    let path = dirs::home_dir().unwrap().join(".config/secrets/vault.qvlt");
    let data = std::fs::read(path)?;
    Ok(Vault::decrypt(&data, passphrase)?)
}

// Use in API calls
let vault = load_user_secrets("passphrase")?;
let api_key = vault.get("OPENAI_API_KEY").unwrap_or_default();
```

## Vault File Format (QVLT)

```
Offset  Size  Description
0       4     Magic: "QVLT"
4       1     Version: 0x01
5       16    PBKDF2 salt (random)
21      12    AES-GCM nonce (random)
33      16    AES-GCM authentication tag
49      N     Ciphertext
```

The plaintext inside the ciphertext uses a compact binary encoding:

```
Repeated:
  [2 bytes BE] key length
  [N bytes]    key (UTF-8)
  [4 bytes BE] value length
  [N bytes]    value (UTF-8)
Terminated by:
  [0x00 0x00]
```

This format is binary-compatible with the [Zig implementation](https://github.com/quantum-encoding/quantum-zig-forge) — either can read the other's vault files.

## Cryptography

| Component | Algorithm | Specification |
|-----------|-----------|--------------|
| Encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | PBKDF2-HMAC-SHA256 | RFC 8018, 600k iterations |
| Salt | Random | 128-bit, fresh per save |
| Nonce | Random | 96-bit, fresh per save |

**Security properties:**
- Authenticated encryption — tampered data is rejected, not decrypted to garbage
- Fresh salt + nonce per save — identical data produces different ciphertext each time
- PBKDF2 at 600k iterations — OWASP 2023 minimum recommendation for SHA-256
- Memory zeroing — `Drop` impl overwrites all secret values before deallocation
- No partial decryption — wrong passphrase = immediate GCM auth failure

## Environment Variables

| Variable | Description |
|----------|------------|
| `SECRETS_PASSPHRASE` | Vault passphrase for non-interactive use |
| `SECRETS_DIR` | Override vault directory (default: `~/.config/secrets`) |

## Comparison

| Tool | Encryption | Dependencies | Size | Platforms |
|------|-----------|-------------|------|-----------|
| **secrets-vault** | AES-256-GCM + PBKDF2 | 4 (lib) | 508 KB | macOS, Linux |
| pass | GPG | gpg, bash, git, tree | ~50 MB | macOS, Linux |
| 1Password CLI | AES-256-GCM | Proprietary | ~30 MB | macOS, Linux, Windows |
| dotenvx | AES-256-GCM | Node.js | ~80 MB | macOS, Linux, Windows |

## License

MIT
