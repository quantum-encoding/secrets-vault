# secret_cli (crate: `secrets-vault`)

## Elevator pitch
AES-256-GCM encrypted key-value vault for API keys and tokens — single Rust crate that ships both a `secrets` CLI and an embeddable library, with a binary-compatible QVLT file format shared with a sibling Zig implementation.

## Problem solved
Developers normally keep API keys as plaintext `export FOO=...` lines in `~/.zshrc` (or `.env` files), so any process or AI agent that reads shell config gets every credential. `secrets-vault` replaces that with one encrypted file: secrets live in `~/.config/secrets/vault.qvlt` (AES-256-GCM, PBKDF2-SHA256 @ 600k iters), and a single shell line — `eval $(secrets env 2>/dev/null)` — restores them at shell startup. Targeted at individual developers and small tools that want a `pass`-style workflow without depending on GPG, Node, or a proprietary daemon.

## Architecture overview
- **Library/binary split** in one crate (`Cargo.toml`): `src/lib.rs` is the pure-crypto core (4 deps: `aes-gcm`, `pbkdf2`, `sha2`, `zeroize`); `src/main.rs` is the CLI binary, gated behind a `cli` feature that pulls in `clap`, `rpassword`, `dirs`, `atty`.
- **`Vault` type** wraps a `BTreeMap<String, String>` (sorted = deterministic plaintext order). `encrypt` / `decrypt` are the only crypto entry points; a `Drop` impl `zeroize`s every value on the way out.
- **QVLT file format**: 49-byte header (`"QVLT"` magic + version byte + 16-byte salt + 12-byte nonce + 16-byte GCM tag) followed by ciphertext. Plaintext payload is a compact length-prefixed `[u16 klen][key][u32 vlen][value]` stream terminated by `0x0000`. Format is intentionally identical to the Zig sibling project so vaults are interchangeable.
- **Crypto**: random salt + random nonce per save (so re-encrypting the same data produces different bytes); PBKDF2-HMAC-SHA256 at OWASP-2023's 600,000 iterations; GCM auth tag gives tamper detection / wrong-passphrase rejection in one step.
- **CLI surface** (`secrets <subcmd>`): `set`, `get`, `delete`, `list`, `env [--json]`, `import` (parses `KEY=VALUE` / `export KEY=VALUE` from stdin), `export`. Passphrase comes from `$SECRETS_PASSPHRASE` or a hidden TTY prompt; vault path is `$SECRETS_DIR/vault.qvlt` or `~/.config/secrets/vault.qvlt`. On Unix, the parent dir is chmod 700 and the file is opened 0600.

## Key files to read first
- `src/lib.rs` — entire crypto core, QVLT serializer/deserializer, `Vault` API, and unit tests (round-trip, wrong-passphrase, tamper detection, fresh-nonce, shell escaping, env parsing).
- `src/main.rs` — `clap` subcommands and the `load_vault` / `save_vault` flow, including the Unix-only secure-permissions code path.
- `Cargo.toml` — feature flags, the lib/bin split, and the release profile (`opt-level = "z"`, LTO, strip).
- `README.md` — user-facing install, Keychain auto-unlock recipe, format spec, and comparison table vs `pass` / 1Password CLI / dotenvx.
- `findings.md` — red-team audit notes worth reading before changing anything security-relevant.

## External dependencies
- Library (always): `aes-gcm 0.10`, `pbkdf2 0.12`, `sha2 0.10`, `zeroize 1.6` — all pure Rust, no `openssl`.
- CLI feature only: `clap 4` (derive), `rpassword 7`, `dirs 5`, `atty 0.2`.
- MSRV: Rust 1.70. No build scripts, no C deps. Published on crates.io as `secrets-vault` v1.0.0 (MIT).

## Build / run
```bash
# Build + test
cargo build --release          # ./target/release/secrets (~508 KB)
cargo test                     # runs the unit tests in src/lib.rs

# Library-only (no CLI deps)
cargo build --no-default-features

# Install from source / crates.io
cargo install --path .
cargo install secrets-vault

# Run
secrets set ANTHROPIC_API_KEY "sk-ant-..."
secrets list
eval $(secrets env)
SECRETS_PASSPHRASE=… secrets get OPENAI_API_KEY
```
