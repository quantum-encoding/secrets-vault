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
secrets gen KEY           Generate a random secret and store it — value NEVER printed
secrets get KEY           Retrieve a secret (stdout, no trailing newline)
secrets delete KEY        Remove a secret
secrets list              List all key names (sorted)
secrets env               Output all as export KEY='VALUE' for eval
secrets env --json        Output as JSON object
secrets import            Import KEY=VALUE lines from stdin
secrets export            Export all as KEY=VALUE
secrets --version         Show version

# macOS — biometric vault + agent-safe scoped injection (see section below)
secrets unlock [--strict] Store the master key in the biometric Keychain (Touch ID)
secrets lock              Remove the biometric Keychain entry
secrets exec P -- CMD     Run CMD with ONLY project P's secrets in its environment
secrets authorize A P     Grant agent A access to project P (Touch ID)
secrets revoke A P        Revoke an agent's access to a project (Touch ID)
secrets list-projects     Show registered projects + agent grants (Touch ID)
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

## Agent-Safe Secrets: biometric vault + scoped `exec` (macOS)

> `eval $(secrets env)` dumps your **entire** vault into the shell environment, where
> every child process — including untrusted `npm`/`pip` postinstall scripts and AI
> coding agents — inherits all of it. The features below replace that footgun with a
> biometric-gated vault and **per-project, child-only** secret injection.

### 1. Biometric unlock (Touch ID / Secure Enclave)

```bash
secrets unlock            # type the vault passphrase once → stored behind Touch ID
```

The master passphrase lives in a data-protection Keychain item in a **team-prefixed
access group**, protected by a `SecAccessControl`. Only this Developer-ID-signed
binary can reach it, and only after a Touch ID tap — a background `evilpackage`
running `security find-generic-password` gets nothing. After `unlock`, every read
surfaces the native Touch ID sheet **even from a headless/agent process** (it routes
to your display and blocks until you tap). `secrets lock` removes the item.

### 2. Scoped execution — `secrets exec`

Declare which secrets a project needs in a `.secrets.toml` manifest (names only —
values stay in the vault), then run a command with **only** those keys in its
environment, injected at spawn and visible to **no other process**:

```toml
# .secrets.toml  (in your project root)
[projects.myapp]
secrets = ["DATABASE_URL", "STRIPE_SECRET_KEY"]
```

```bash
secrets exec myapp -- cargo run
# → one Touch ID tap, decrypts ONLY those keys, injects into cargo's env, zeroizes.
```

`exec` does exactly **one** Keychain read and decrypts the whole batch in a single
vault-open, then wipes the plaintext from its own memory before the child starts.

### 3. Generate without scrollback exposure

```bash
secrets gen SESSION_TOKEN           # 32 random bytes → stored; value never printed
secrets gen API_KEY --bytes 64      # custom length
```

### 4. Agent authorization (who may use what)

When a recognized AI agent (Claude, etc.) drives `secrets exec`, the CLI resolves the
calling agent from the process ancestry and requires an explicit grant:

```bash
secrets authorize claude myapp                       # permanent grant (Touch ID)
secrets authorize claude myapp --session-minutes 15  # timed grant
secrets revoke    claude myapp
secrets list-projects                                # inspect grants
```

Grants are stored in an **encrypted, biometric-gated registry** (`registry.enc`) —
metadata only, never secret values. An ungranted agent fails closed (or requests
real-time approval via the **aiconductor** desktop app — see `APPROVAL_PROTOCOL.md`).
Process-ancestry agent ID is a *soft* layer (spoofable by a same-user adversary); the
hard boundary is the Touch ID tap.

### 5. Google Secret Manager backend

Point a project at GSM and values are pulled live from Secret Manager (via `gcloud`,
never the local vault). Secret values transit `gcloud` stdin/stdout — never argv.

```toml
# .secrets.toml
[gsm]
project = "my-gcp-project"          # acting identity needs secretAccessor / secretVersionAdder
secrets = ["DATABASE_URL", "API_KEY"]
```

```bash
secrets set  API_KEY "value" --gsm --project my-gcp-project   # write to GSM
secrets gen  API_KEY         --gsm --project my-gcp-project   # generate → GSM
secrets exec myapp -- ./deploy.sh                              # exec pulls from GSM
```

### 6. Strict mode — close the Touch ID grace window

A normal (`UserPresence`) unlock honors macOS's **system Touch ID reuse grace**: after
one tap, a burst of reads flows without re-prompting (convenient for agent runs, but a
concurrent malicious read could ride that window). Strict mode trades that for a fresh
tap on every access:

```bash
secrets unlock --strict
```

This stores the item with `BiometryCurrentSet` (enrolled biometry **only** — no
watch/passcode fallback; self-invalidates if the fingerprint set changes) and attaches
a zero-reuse `LAContext` (`touchIDAuthenticationAllowableReuseDuration = 0`) on every
read. Re-run plain `secrets unlock` to return to the convenient mode.

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
| `SECRETS_PASSPHRASE` | Vault passphrase for non-interactive use (bypasses Keychain) |
| `SECRETS_DIR` | Override vault directory (default: `~/.config/secrets`) |
| `SECRETS_GSM_ACCOUNT` | Override the active `gcloud` account for the GSM backend |
| `SECRETS_GSM_IMPERSONATE` | Service account to impersonate for GSM access |
| `SECRETS_APPROVAL_DIR` | Approval handshake dir (default: `~/.secrets/pending_approvals`) |
| `SECRETS_APPROVAL_TIMEOUT_SECS` | Real-time approval wait before failing closed (default: 30) |

## Comparison

| Tool | Encryption | Dependencies | Size | Platforms |
|------|-----------|-------------|------|-----------|
| **secrets-vault** | AES-256-GCM + PBKDF2 | 4 (lib) | 508 KB | macOS, Linux |
| pass | GPG | gpg, bash, git, tree | ~50 MB | macOS, Linux |
| 1Password CLI | AES-256-GCM | Proprietary | ~30 MB | macOS, Linux, Windows |
| dotenvx | AES-256-GCM | Node.js | ~80 MB | macOS, Linux, Windows |

## License

MIT
