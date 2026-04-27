# secret_cli — Red-Team Audit

**Scope:** `src/lib.rs`, `src/main.rs`, `Cargo.toml` @ commit `c8e3962`.
**Crypto stack:** AES-256-GCM + PBKDF2-HMAC-SHA256 (600k) — sound.
**Headline:** the crypto is fine. The leaks are around it — argv, env, scrollback, atomicity. Two HIGH-impact issues a competent local attacker walks through.

---

## HIGH

### H1 — Secret on argv via `secrets set KEY VALUE` (lib enables it, CLI exposes it)
**File:** `src/main.rs:21`, accepts `value: Option<String>`.

```
$ secrets set STRIPE_KEY sk_live_deadbeef
```
…now sits in:
- `~/.zsh_history` / `~/.bash_history` (forever)
- `/proc/<pid>/cmdline` while the process runs (readable to other UIDs depending on hidepid; readable to same-UID always)
- macOS `ps -E` / Linux `ps -ef` snapshot
- shell-tracing tools, `script(1)`, audit logs, container exec layers

**Exploit:** any CI runner / shared box / coworker watching `ps` while a deploy script runs `secrets set TOKEN $X` captures the cleartext. The whole point of this tool is to *avoid* dropping secrets in dotfiles — and the default `set` ergonomic does exactly that.

**Fix:** drop the positional `value` arg. Force stdin / TTY-prompt. Or refuse to accept it from argv if `isatty(stdin)` is true and emit a hard error pointing at `secrets set KEY` (prompt) or `echo $X | secrets set KEY` (pipe).

---

### H2 — Master passphrase via `$SECRETS_PASSPHRASE`
**File:** `src/main.rs:51`.

```rust
if let Ok(pass) = env::var("SECRETS_PASSPHRASE") {
    return Zeroizing::new(pass);
}
```

Env vars are inherited by every child process and exposed at `/proc/<pid>/environ` (same-UID readable on Linux). Setting this in `~/.zshrc` for convenience leaks the *master key for every secret* into every npm/cargo/git subprocess, every Docker layer that inherits env, every crash-dump tool that snapshots env.

**Exploit:** malicious npm postinstall reads `/proc/self/environ`, exfils `SECRETS_PASSPHRASE`, attacker now has the master key — every secret, forever. The product's threat model (don't put secrets in env) is violated by the product itself.

**Fix:** keep the env path but rename to `SECRETS_PASSPHRASE_UNSAFE`, document the trade-off, or hide it behind a `--passphrase-from-env=NAME` flag so the choice is intentional rather than ambient.

---

### H3 — Non-atomic vault write — power-loss / SIGKILL = total vault loss
**File:** `src/main.rs:107-118`.

```rust
let mut file = fs::OpenOptions::new()
    .write(true).create(true).truncate(true)   // ← truncate before write
    .mode(0o600).open(&path)...
io::Write::write_all(&mut file, &encrypted).unwrap();
```

`truncate(true)` zeroes the file *before* the new bytes are written. Crash, OOM kill, container eviction between truncate and write_all → vault is 0 bytes, every secret is gone, no recovery. No `fsync`, no tmpfile + rename.

**Exploit:** not adversarial — operational. But equivalent to data loss on `kill -9`.

**Fix:** write to `vault.qvlt.tmp` with 0o600, `file.sync_all()`, then `fs::rename(tmp, final)`. Optionally fsync the parent dir.

---

## MEDIUM

### M1 — `to_shell_exports()` / `to_json()` / `Get` bypass `Drop`-zeroing
**File:** `src/lib.rs:260-283`, `src/main.rs:164,193,195`.

`Drop for Vault` zeroes values on the way out — good intent. But every export path *clones* values into a fresh `String` before printing:

- `to_shell_exports` builds `String` containing every secret → returned, printed, leaked into stdout buffer / pty scrollback / `eval $(...)` shell memory. Not zeroed.
- `to_json` same.
- `print!("{value}")` on `Get` — copy lives in libc stdout buffer, not zeroed.

The `Drop` impl gives a false sense of "memory hygiene" while the actual hot path leaves heap copies behind. `Zeroizing<String>` for the assembled output (and explicit drop after `print!` + flush) would actually do something.

### M2 — Keys are not zeroed
**File:** `src/lib.rs:292-302`.

```rust
for value in self.entries.values_mut() { ... }
```

Only values are zeroed. Key names (`STRIPE_LIVE_SECRET_KEY`, `OPENAI_PROD_KEY`) often *are* themselves sensitive metadata — leaks operational footprint. Iterate `entries.iter_mut()` and zero both. (`String` keys in `BTreeMap` are not trivially mutable in place — needs `mem::take` + drain, but doable.)

### M3 — PBKDF2 derived key not zeroized after encrypt/decrypt
**File:** `src/lib.rs:392-396`.

```rust
let key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(...);
*Key::<Aes256Gcm>::from_slice(&key)
```

Two copies live: the local `key: [u8; 32]` (dropped without zeroize — the array's `Drop` is no-op) and the dereferenced copy installed in `Aes256Gcm`. `aes-gcm` 0.10's `Aes256Gcm` zeroizes its expanded round keys on drop (verify), but the raw `[u8; 32]` here does not. Wrap the local in `zeroize::Zeroizing<[u8; 32]>`.

`drop(cipher)` on `lib.rs:204` is a no-op marker comment, not a security primitive — it just expresses "I want this dropped here", which it already is at scope end. Doesn't actually do extra work.

### M4 — `$SECRETS_DIR` is unvalidated and joined directly
**File:** `src/main.rs:40-42`.

```rust
if let Ok(dir) = env::var("SECRETS_DIR") {
    return std::path::PathBuf::from(dir).join("vault.qvlt");
}
```

No path canonicalisation, no constraint that it's inside `$HOME`, no symlink check. If a hostile process can set the env (e.g. parent shell compromise) before the user runs `secrets set`, they redirect writes to `SECRETS_DIR=/tmp/attacker-watched/`. Combined with the user supplying the passphrase, the attacker now holds the encrypted vault file under a path *they* can read. Then offline-crack at leisure (PBKDF2-SHA256 600k → ~150 H/s/GPU-thread, weak passphrases die).

**Fix:** require `SECRETS_DIR` to be absolute, refuse symlinks via `fs::symlink_metadata`, document trust model.

### M5 — Parent-dir 0700 set *after* `create_dir_all` — TOCTOU window
**File:** `src/main.rs:90-96`.

`create_dir_all` honours umask (typically 0o755 → world-readable). Only the leaf `secrets/` dir gets retro-chmod'd to 0700. Race window during first run: another local user lists `~/.config/secrets/` between `create_dir_all` and `set_permissions`. Tiny window, but the fix is trivial: use `DirBuilder::new().mode(0o700).recursive(true)` on Unix. Also: the chmod is applied only to `parent`, not all newly-created ancestors.

### M6 — Plaintext intermediate buffers escape zeroize
**File:** `src/lib.rs:189-215`.

`encrypt()` does `let mut plaintext = serialize(&self.entries);` → encrypts in place → writes the (now-cipher) buffer to `out`. Good. **But** `serialize` returns a `Vec<u8>` that's never explicitly zeroed; if AES-GCM `encrypt_in_place_detached` fails (memory pressure, panic), the unencrypted `plaintext` Vec drops with secret bytes still in heap memory. In normal-path the buffer *is* overwritten by ciphertext, so contents are gone — but only because of crypto, not policy.

Wrap `plaintext` in `Zeroizing<Vec<u8>>` for belt-and-braces.

### M7 — `String::from_utf8_lossy` silently mangles values on deserialize
**File:** `src/lib.rs:370,383`.

```rust
let key = String::from_utf8_lossy(&data[pos..pos + klen]).to_string();
```

After GCM auth, the bytes ARE trusted — but if the original caller stored bytes via `entries_mut().insert("X", String::from_utf8_unchecked(...))` (perfectly possible from the lib API), round-trip silently replaces invalid UTF-8 with U+FFFD. Loud `MalformedData` is safer than corruption.

### M8 — DoS: `Vault::decrypt` reads entire blob into RAM, then clones it
**File:** `src/lib.rs:242` `let mut buf = ciphertext.to_vec();`.

Caller passes `data: &[u8]`. CLI does `fs::read(&path)` first. If `$SECRETS_DIR` points at a 50 GB sparse file (or attacker drops `vault.qvlt` with 50 GB of trailing junk), we OOM. Bound the file size before reading: `metadata().len() < MAX_VAULT_BYTES`.

---

## LOW / INFO

### L1 — No KDF params in header
600k iterations is hardcoded. Bumping it later breaks every existing vault unless you bump `VERSION` and branch. Storing `iter_count: u32` in the header (4 bytes, GCM-authenticated) future-proofs it. Same applies if you ever migrate to Argon2id.

### L2 — Empty AAD
`encrypt_in_place_detached(&nonce, b"", &mut plaintext)`. Header bytes (magic, version, salt, nonce) are *implicitly* protected (tampering with salt → wrong key → auth fail; tampering with version fails the pre-check). But binding `AAD = magic || version || salt || nonce` is one line and gives explicit cross-version replay resistance.

### L3 — `to_json` is not RFC-8259 compliant
Only `\\` and `"` are escaped. A value containing a literal newline, tab, control byte, or backslash-followed-by-non-special produces invalid JSON. Strict parsers will reject; lenient ones may misinterpret. Use `serde_json` or hand-escape the full set (`\b \f \n \r \t \u00xx`).

### L4 — `parse_env_lines` strips quotes too aggressively
`trim_end_matches(|c| c == '"' || c == '\'')` strips *any number of trailing quotes*, so `KEY="value"` and `KEY="value\"`'`""` both parse the same way. Quote-handling for env files should be character-pair based, not character-set based.

### L5 — Pipe-mode `Set` doesn't strip `\r`
`src/main.rs:144` — `trim_end_matches('\n')` only. A Windows-pipe (`echo X | secrets set K`) leaves `\r` in the value. Stored secret silently includes `\r` and breaks downstream consumers (`curl -H "Auth: $X"` etc.).

### L6 — No file lock on read-modify-write
Concurrent `secrets set A` + `secrets set B` from two shells: both load, both modify, both save. Last writer wins, the other key is silently lost. Use `flock(2)` (Unix) on the vault file across the load/save critical section.

### L7 — Typo on first-ever `set` produces a permanently unrecoverable vault
No "confirm passphrase" prompt on initial creation (the case where `fs::read(&path) == NotFound`). One typo and the vault is encrypted with a passphrase the user can't reproduce. Standard mitigations: confirm on creation, or require explicit `secrets init` step.

### L8 — `dirs::home_dir().expect("HOME not set")`
Daemons / sandboxes / cron without `$HOME` panic with stack trace. Cosmetic, not security.

### L9 — Drop trait won't run on `process::exit`
`process::exit(1)` (called from many error paths in `main.rs`) bypasses `Drop`. Vault values held at exit time are *not* zeroed. Practical impact: small (process is ending anyway), but the zeroize story is slightly weaker than advertised.

---

## What's NOT a problem (worth noting since you asked for paranoia)

- **Crypto choice:** AES-256-GCM + PBKDF2-SHA256@600k is OWASP-aligned. Random salt + nonce per save is correct. No nonce reuse risk since both are fresh from `OsRng` on every encrypt.
- **GCM tag covers ciphertext:** tamper detection works (tested in `tamper_detection`). Header-byte flips fail closed via the magic/version pre-check or via key-derivation mismatch.
- **`unsafe` block in `Drop`:** writing 0x00 into a `String` via `as_bytes_mut()` is sound — NUL is valid UTF-8.
- **No `Command::new` / `process::Command` anywhere:** no command-injection surface.
- **No deserialization of attacker-controlled formats** (the binary format is bespoke and only parsed *post-GCM-auth*). Pre-auth parsing is just length checks.
- **No JWT, no log SSRF, no debug logging of secrets.**
- **`Zeroizing<String>` wraps the passphrase in `main.rs`** — passphrase memory hygiene is correct on the CLI path.

---

## Priority fix list (1 hour of work)

1. **H1** — kill positional value on `Set`. Force stdin/prompt. (5 lines.)
2. **H3** — atomic write: tmp → fsync → rename. (10 lines.)
3. **M4** — refuse non-absolute or symlinked `SECRETS_DIR`. (3 lines.)
4. **L7** — confirm passphrase on initial vault creation. (8 lines.)
5. **H2** — rename env var to `SECRETS_PASSPHRASE_UNSAFE` and document the foot-gun, OR gate behind explicit `--passphrase-env`.

Those five take the tool from "good crypto, leaky harness" to "actually defendable in the threat model it claims."
