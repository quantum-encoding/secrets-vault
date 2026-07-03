# CLAUDE.md — `secrets` vault CLI

Guidance for AI agents (Claude Code and others) both **using** `secrets` to handle
credentials and **modifying** this CLI. `secrets` is a Developer-ID-signed Rust CLI
that replaces plaintext `export KEY=…` dotfiles with an AES-256-GCM vault whose master
key lives behind **Touch ID** in the macOS Keychain, plus per-project **child-only**
injection so a command sees only the keys it declared.

Repo: `quantum-encoding/secrets-vault` · Binary installs to `~/.local/bin/secrets`.

---

## Non-negotiable rules when handling secrets

These are the whole point of the tool — an agent that breaks them defeats it:

1. **Never print a secret value** to stdout, logs, or scrollback. To confirm a read
   worked, measure bytes — `secrets get KEY | wc -c` — never echo the value.
2. **Values never go in argv** (they show up in `ps`). Pass secrets only via **stdin**,
   the child's **env** (`secrets exec`), or a backend reference. When a consumer needs a
   secret in an HTTP header, feed it through stdin, not `-H "Bearer $TOK"`:
   ```bash
   # curl reads the auth header from a stdin config — token never in argv:
   secrets get API_TOKEN \
     | sed 's/.*/header = "Authorization: Bearer &"/' \
     | curl -sS -K - "https://api.example.com/v1/whoami"
   ```
3. **You (the agent) cannot self-approve.** The unforgeable boundary is the human's
   Touch ID tap. The native prompt appears **on the user's screen** when you run a
   `secrets` command from a tool shell — tell them to watch for it; it won't appear to you.
4. **Generating > setting.** Prefer `secrets gen KEY` (value is never printed) over
   `secrets set KEY "value"` (value in argv). To store a value produced by another
   command, pipe it in — see "Storing a value you must not see" below.

## Everyday operations

```bash
secrets set  KEY               # interactive TTY: masked prompt, shows • per char, never echoes
echo -n v | secrets set KEY    # non-TTY: value read from stdin automatically (not argv)
secrets gen  KEY [--bytes 64]  # generate random secret; value NEVER printed
secrets get  KEY               # read to stdout — pipe to a consumer, don't echo
secrets has  KEY               # existence check, NO Touch ID (reads the plaintext name index)
secrets list --names-only      # names only, no unlock/tap
secrets delete KEY
secrets import                 # ingest `KEY=VALUE` lines from stdin (agent-friendly store)
```

`secrets set KEY` with no value: if stdin is a TTY it shows a **masked prompt** (bullets
indicate length as you type — Backspace erases one, Enter submits, Ctrl-C aborts). If
stdin is **not** a TTY (piped/redirected) it reads the value from stdin. Either way the
value never touches argv.

### Storing a value you must not see (agent relay pattern)

When you fetch a credential from an API and must land it in the vault without it ever
transiting your context, pipe the extractor straight into `secrets import`:

```bash
create_token_somehow \
  | python3 -c "import sys,json; sys.stdout.write('NEW_KEY='+json.load(sys.stdin)['value'])" \
  | secrets import
# value existed only inside the pipe and the encrypted vault — never argv, never printed
```

## Scoped execution — the safe way to give a command secrets

Declare needs in `.secrets.toml` (names only; see `.secrets.toml.example`), then:

```bash
secrets exec myapp -- cargo run   # one tap; injects ONLY those keys into cargo's env
```

`exec` resolves the calling agent from process ancestry and requires a grant, else it
fails closed. The **user** authorizes (Touch ID):

```bash
secrets authorize claude myapp                       # permanent
secrets authorize claude myapp --session-minutes 15  # timed
secrets revoke    claude myapp
```

Prefer `exec` over `eval $(secrets env)` (which dumps the whole vault into the shell).

## First-run / troubleshooting

- "Can't read the vault" → the user must run `secrets unlock` once (stores the master key
  behind Touch ID). Until then, reads fall back to a TTY passphrase and fail closed when headless.
- `secrets unlock --strict` forces a fresh tap on every access (no grace window).
- Backends: local vault (default), Google Secret Manager (`[gsm]` in `.secrets.toml`), or
  any CLI-driven manager (`[backend] kind = "command"`). See README §5b.

---

## Modifying this CLI — build → SIGN → install (do not skip signing)

The biometric Keychain master key is bound to the binary's **code signature**. Rebuilding
strips the signature, so after any source change you MUST re-sign and reinstall or the
freshly built binary gets `-34018` (missing entitlement) on Keychain access:

```bash
cargo build --release && ./sign.sh && cp target/release/secrets ~/.local/bin/secrets
```

`sign.sh` uses the stable **Developer ID Application** cert + `secrets.entitlements`
(the `keychain-access-groups` entitlement). The access group is stable across rebuilds,
so previously-stored items stay reachable — re-signing is safe and does not orphan the vault.
Verify no regression after installing with `secrets has SOME_KEY` (no tap) then
`secrets get SOME_KEY | wc -c` (Touch ID — proves the new signature can still reach the key).

### Source map

| File | Responsibility |
|---|---|
| `src/lib.rs` | Vault crypto core (AES-256-GCM, PBKDF2, zeroize) — pure Rust, no CLI deps |
| `src/main.rs` | CLI: arg parsing, prompts (incl. masked `read_masked`), command dispatch |
| `src/keychain.rs` | macOS Touch ID Keychain read/write (Secure Enclave master key) |
| `src/registry.rs` | Encrypted agent→project grant registry (metadata only, no values) |
| `src/backend.rs` | Generic external secret-manager backend (`[backend] kind="command"`) |
| `src/gsm.rs` | Google Secret Manager backend |
| `src/inbox.rs` | Write-only sealed inbox (age/X25519) — seal with no tap, merge behind one tap |

### Conventions

- **Never** widen a code path so a secret can reach argv, a log line, or an un-zeroized
  buffer. Wrap plaintext in `zeroize::Zeroizing` and pass by stdin/env only.
- macOS is the primary target (Touch ID). Gate `libc`/Keychain code behind
  `#[cfg(target_os = "macos")]` with a non-macOS fallback so the crate still builds elsewhere.
- Keep the library (`lib.rs`) CLI-dep-free; CLI-only crates live under the `cli` feature.
