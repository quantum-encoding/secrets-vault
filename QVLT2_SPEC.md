# QVLT v2 — Per-Entry Vault Encryption

**Status: DRAFT — not yet implemented.** Companion to [`BROKER_PROTOCOL.md`](./BROKER_PROTOCOL.md)
(approval-dialog election) and [`APPROVAL_PROTOCOL.md`](./APPROVAL_PROTOCOL.md) (grant
handshake). This doc specifies the successor vault file format and the session-broker
protocol change that together end the "one tap opens the entire jewel room" property
of v1.

---

## 1. Why v1 has to go

v1 (`src/lib.rs`, magic `QVLT`, version `0x01`) is a **single AES-256-GCM blob**: one
PBKDF2 key derived from the passphrase encrypts *all* entries serialized together.
Structural consequences:

1. **Every read decrypts everything.** `secrets get ONE_KEY` runs `Vault::decrypt`,
   which materializes every secret in the vault as plaintext in process memory, then
   picks one. The format has no per-entry boundary, so this is not fixable by code
   discipline — only by a new format.
2. **`exec` scoping is policy, not cryptography.** The "inject only declared keys"
   guarantee is an in-memory filter applied *after* full decryption. A compromised or
   memory-dumped process during any operation sees the whole vault.
3. **The session broker (`src/session.rs`) serves the master passphrase itself.**
   Any same-uid caller that connects during a session window receives the key to the
   entire vault. A real ssh-agent never releases the private key — it performs
   operations on the holder's behalf. Ours mails the key when asked.

One v1 property is worth **preserving deliberately**: whole-blob GCM means an attacker
with file-write access cannot delete, reorder, or transplant individual entries
undetected. A naive per-entry format loses that; v2 restores it with a manifest MAC
(§4.4) plus per-entry AAD binding (§4.3).

## 2. Goals and non-goals

**Goals**

- G1: `secrets get KEY` decrypts **exactly one** value. All other ciphertexts stay
  ciphertext; no full-vault plaintext ever exists in memory for single-key reads.
- G2: `secrets exec` decrypts exactly the declared key set.
- G3: `secrets set`/`gen`/`delete`/`import` write **without decrypting unrelated
  entries** (§5.2).
- G4: The session broker never releases the passphrase or master secret; it serves
  individual, grant-checked values (§6).
- G5: Integrity ≥ v1: per-entry tamper detection, plus detection of entry deletion,
  duplication, reordering, and cross-entry transplants.
- G6: One expensive KDF per open (PBKDF2 600k stays at vault level; per-entry keys are
  cheap HKDF derivations).
- G7: Room for Phase 3 (per-project scope keys / sealed writes, §7) without another
  format break.

**Non-goals**

- Rollback protection against an attacker who replaces the *entire vault file* with an
  older complete copy. v1 doesn't have this either; it requires external state (e.g.
  a monotonic counter in the Keychain) and is deferred to Phase 3 consideration.
- Hiding key *names*. Names are non-secret by design throughout the tool
  (`index.json`, `secrets has`, `list --names-only`, `.secrets.toml` manifests).
- Multi-writer concurrency. Writes remain whole-file atomic replace, last-writer-wins,
  same as v1.
- Binary compatibility with the Zig implementation. **v2 breaks it** (decision
  recorded here); the Zig port can adopt v2 separately if ever needed.

## 3. Threat-model delta

| Scenario | v1 | v2 |
|---|---|---|
| Process memory captured during `get KEY` | all values exposed | one value + master secret* exposed |
| Compromised same-uid process during session window | full passphrase → whole vault, offline, forever | per-key values, only for granted (agent, project) pairs, only while broker lives |
| Attacker edits one entry in the file | detected (blob MAC) | detected (entry GCM tag) |
| Attacker deletes/reorders/duplicates entries | detected (blob MAC) | detected (manifest MAC) |
| Attacker swaps ciphertext between two names | detected (blob MAC) | detected (AAD = name) |
| Whole-file rollback to older valid vault | undetected | undetected (non-goal, see above) |

\* The master secret in memory during a CLI read is unavoidable while the CLI does its
own decryption; the broker path (§6) removes even that from client processes — the
client receives only the requested plaintext value.

## 4. File format

Container: magic stays `QVLT`; version byte becomes `0x02`. v1 binaries reading a v2
file fail cleanly with `unsupported vault version: 2` (fail closed, no misparse).

All integers are big-endian, matching v1's serializer.

```text
── Header ──────────────────────────────────────────────
[4]   Magic            "QVLT"
[1]   Version          0x02
[16]  Vault salt       PBKDF2 salt — stable across saves (§5.1)
[4]   u32 entry count

── Entry record × count (sorted by name, byte-lexicographic) ──
[1]   Key scheme       0x01 = HKDF-from-master (this spec)
                       0x02 = reserved: scope-sealed X25519 (Phase 3, §7)
[2]   u16 name length  (1..=256+257 — allows "project/KEY" scoped names)
[N]   Name             plaintext UTF-8, validated per is_valid_key / scoped_key
[12]  AES-GCM nonce    fresh random per write of this record
[16]  AES-GCM tag
[4]   u32 ct length    (≤ MAX_VALUE_LEN)
[C]   Ciphertext

── Trailer ─────────────────────────────────────────────
[32]  Manifest MAC     HMAC-SHA256(mac_key, file[0 .. len−32])   (§4.4)
```

### 4.1 Key derivation

```text
master_secret = PBKDF2-HMAC-SHA256(passphrase, vault_salt, 600_000)      # 32 B, once per open
entry_key     = HKDF-SHA256(ikm = master_secret, salt = vault_salt,
                            info = "qvlt2 entry:" || name)               # 32 B, per entry
mac_key       = HKDF-SHA256(ikm = master_secret, salt = vault_salt,
                            info = "qvlt2 manifest")                     # 32 B
```

PBKDF2 (the 600k-iteration cost) runs once per open — G6. HKDF expansions are
per-entry and effectively free. `master_secret` and every derived key are held in
`Zeroizing` buffers.

There is no wrapped-DEK table: the per-entry key is a pure derivation from
(master_secret, name). Simpler format, nothing extra to keep consistent, and entry
keys never touch the file.

### 4.2 Entry encryption

Each value is encrypted independently:

```text
ciphertext, tag = AES-256-GCM-Encrypt(entry_key, nonce, aad, value)
```

### 4.3 AAD binding

`aad = version_byte || scheme_byte || name` (name bytes exactly as stored in the
record). A record decrypted under the wrong name fails authentication — ciphertext
transplants between names are structurally impossible, enforced by the AEAD itself
rather than by code that remembers to check. This holds even if a buggy code path
skips the manifest MAC.

### 4.4 Manifest MAC

`HMAC-SHA256(mac_key, file[0 .. len−32])` — over every byte of the file except the MAC
itself. Covers the header, all record metadata, **and** all ciphertexts, restoring
v1's whole-file integrity (G5) while still permitting selective decryption: verifying
the MAC requires hashing the file, not decrypting it.

Readers MUST verify the manifest MAC before trusting the entry list (i.e. before
reporting "key not found" or decrypting anything). Verification failure is a hard
error (`DecryptionFailed`-class), same as a v1 tag failure.

Readers MUST reject files whose declared record lengths don't exactly tile the region
between header and trailer, whose entries are not strictly sorted by name, or that
contain duplicate names — before MAC verification even (cheap structural checks), and
regardless of it.

### 4.5 Unknown schemes

A reader encountering a scheme byte it does not implement MUST fail closed for that
entry (error on direct access; skip is not allowed for `env`/`list` — those error
too, naming the entry). Phase 3 readers will handle `0x02`; v2-only readers refuse.

## 5. Operation semantics

| Operation | v1 behavior | v2 behavior |
|---|---|---|
| `get KEY` | full decrypt | MAC check → derive 1 key → decrypt 1 record (G1) |
| `exec` | full decrypt, filter | MAC check → decrypt exactly the declared keys (G2) |
| `has` / `list --names-only` | plaintext `index.json` | unchanged; index now also rebuildable from the v2 file with **no passphrase** (names are plaintext records) |
| `set` / `gen` / `import` | full decrypt + re-encrypt all | splice records **without decrypting others** (§5.2, G3) |
| `delete` | full decrypt + re-encrypt | remove record, recompute MAC — no decryption |
| `list` (values), `env`, `to_json` | full decrypt | full decrypt (inherently whole-vault; remains discouraged in favor of `exec`) |
| `rekey` (new) | — | full decrypt → fresh salt → re-encrypt all (§5.1) |

### 5.1 Salt lifetime and `rekey`

The vault salt is generated at vault creation and is **stable across saves** — this is
what makes G3 possible: a writer can derive the entry key for the name it's touching
and re-emit every other record's bytes verbatim.

Consequences and mitigations:

- Entry keys are long-lived per (passphrase, salt, name). Re-encrypting the same name
  many times uses fresh random 96-bit nonces under a fixed key — standard random-nonce
  GCM bounds, negligible risk at CLI write volumes.
- A new `secrets rekey` command performs full decrypt → fresh salt → re-encrypt-all,
  and MUST be invoked automatically by any future passphrase-change flow. Recommended
  after revoking a party who may have held the master secret.

### 5.2 Write path (no-read splice)

`set NEW_KEY` on an existing vault:

1. Read file, verify manifest MAC (hash only — no decryption).
2. Derive `entry_key(NEW_KEY)`, encrypt the value, build the record.
3. Re-emit header (count ± 1) + existing records verbatim + new record in sorted
   position; recompute manifest MAC.
4. Atomic replace (write 0600 temp in `~/.secrets`, fsync, rename) and refresh
   `index.json`.

Other entries' plaintexts are never materialized. The same splice serves `delete` and
`import` (batch of records in one rewrite). Note this is stronger than v1 even for
writes: today an agent authorized to *store* a new key transitively reads everything.

### 5.3 Library API sketch (`src/lib.rs`)

`Vault` (decrypt-all) remains for v1 reads and the full-decrypt operations. New:

```rust
pub struct VaultReader { /* parsed header + record index over the raw bytes */ }

impl VaultReader {
    pub fn open(data: &[u8], master: &MasterSecret) -> Result<Self, VaultError>; // structural checks + manifest MAC
    pub fn names(&self) -> impl Iterator<Item = &str>;                          // no decryption
    pub fn decrypt_one(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    pub fn splice(&self, upserts: &[(String, Zeroizing<Vec<u8>>)], deletes: &[String])
        -> Result<Vec<u8>, VaultError>;                                         // §5.2, returns new file bytes
}

pub struct MasterSecret(Zeroizing<[u8; 32]>);   // PBKDF2 output; passphrase discardable after this
```

`MasterSecret` replaces passing the passphrase string around `main.rs`: derive once,
zeroize the passphrase, thread the secret. The `cli` feature keeps `lib.rs` dep-free
apart from the existing crypto crates (`hkdf`/`hmac` join `pbkdf2`/`sha2`).

## 6. Session broker v2 — key server, not passphrase dispenser

Transport unchanged: `~/.secrets/session.sock`, 0600 inside the 0700 dir, daemon
started by `secrets session <min>` via the hidden `__session-serve` (passphrase over
stdin pipe), ended by `secrets lock` / lifetime expiry. What changes is the protocol
and the trust model.

### 6.1 Protocol

Requests are a single line; responses are a status line plus optional exact-length
body (values may contain newlines — multi-line values are supported).

```text
GET <project> <key>\n            → OK <len>\n<len bytes>      one decrypted value
                                 → ERR denied\n               no grant for (caller-agent, project)
                                 → ERR unknown-key\n          not in vault / not in project manifest
                                 → ERR scheme\n               entry uses a scheme the broker can't serve
END\n                            → (connection closed)        shut down now (secrets lock)
```

Removed: the v1 `GET` → raw-passphrase response. The passphrase and `master_secret`
never cross the socket in any form — G4. A v2 broker MUST NOT answer a bare v1 `GET`
line with the passphrase (the argument grammar makes v1 requests unparseable — they
get `ERR denied`).

### 6.2 Server-side enforcement

The v1 broker trusts any same-uid caller with everything. The v2 broker enforces
per-request:

1. **Caller identity**: peer PID via `getsockopt(LOCAL_PEEREPID)` (macOS), then the
   same process-ancestry agent resolution `exec` already uses
   (`registry::resolve_agent`), run **server-side** on that PID — the caller's claim
   about who it is is never consulted.
2. **Grant check**: broker loads `registry.enc` (it holds the passphrase) and requires
   `grant_for(agent, project)` — the identical check `exec` performs, now enforced by
   the party holding the key material.
3. **Manifest check**: the requested key must appear in the project's declared key set
   (`.secrets.toml` names recorded at authorize time / the scoped `project/KEY`
   namespace), so a granted agent still can't enumerate outside its scope.
4. Derive the one entry key from the *current* vault file (re-read per request — a
   `set` during the session window is picked up naturally), decrypt the one record,
   respond, zeroize.

Requests failing any step get `ERR denied` and are logged to stderr→`session.log`
(names and agent only — never values).

### 6.3 Client fallback ordering (`get_passphrase_prompted` successor)

For **reads**, the client tries: `SECRETS_PASSPHRASE` env (unchanged, discouraged) →
broker `GET` (per-key) → Touch ID Keychain read + local v2 selective decrypt → TTY
prompt → fail closed. For **writes** during a session window: the broker is read-only
by design — writes always take the Keychain/TTY path (a tap). Rationale: the session
exists for unattended `exec` drains; humans initiating writes are present to tap.

Consequence, stated plainly: a plain `secrets get KEY` from a human shell during a
session window is **denied by the broker** (no agent, no grant) and falls through to
Touch ID. That is intended — the v1 behavior where a session made *every* same-uid
read tap-free is exactly the "one customer sees everyone's jewels" hole.

## 7. Phase 3 (reserved): cryptographic multi-tenancy

Not specified here; the format reserves for it. Sketch, so the reservation is honest:

- Scheme `0x02`: entry value sealed to a **per-project X25519 keypair** (the age-style
  machinery `src/inbox.rs` already carries). Record layout for `0x02` prepends a
  scheme-specific key-blob (ephemeral pubkey + wrapped key) to the ciphertext field.
- Project private keys live as separate Keychain items (like `inbox-identity`), so a
  broker/session can be granted the ability to open project A's entries while being
  **cryptographically unable** to open project B's — even if fully compromised.
- Sealed writes: `secrets set --project A` needs only A's *public* key — storing a new
  secret requires no unlock at all, extending the inbox model to the main vault.
- A Keychain-held monotonic counter MAC'd into the manifest could close the
  whole-file-rollback non-goal at the same time.

Phase 3 will bump the version byte; v2 readers already fail closed on scheme `0x02`
(§4.5), so partial upgrades are safe.

## 8. Migration

- **Explicit**: `secrets migrate` — one unlock, read v1, write v2 atomically,
  preserving the v1 file as `vault.qvlt.v1.bak` (0600; it is ciphertext under the same
  passphrase — delete it once confident).
- **Implicit**: any operation that already performs a v1 full decrypt-and-save
  (`set`, `gen`, `delete`, `import` on a v1 file) writes v2 output — the work is
  identical, so there is no reason to emit the legacy format. The upgrade is noted on
  stderr once.
- Reads keep v1 support for at least one release cycle (version-byte dispatch).
  Writes never produce v1. A v2 binary must never silently *downgrade* a v2 file.
- The session broker refuses to start (`secrets session`) against a v1 vault: print
  the migrate hint and exit non-zero, rather than reviving the passphrase-dispenser
  behavior.
- Docs to update in the same change: `CLAUDE.md` (§first-run), `README.md` §5,
  `AGENT_SECRET_LIFECYCLE.md`, and the Zig-compat claim in `lib.rs`'s module docs.

## 9. Implementation order

1. **lib.rs**: v2 serializer/parser, `MasterSecret`, `VaultReader` (open / decrypt_one
   / splice), `rekey`; unit tests incl. transplant, deletion, reorder, duplicate-name,
   truncation, and unknown-scheme vectors.
2. **main.rs**: thread `MasterSecret`; route `get`/`exec` through `decrypt_one`,
   writes through `splice`; `migrate` + `rekey` commands; v1 read fallback.
3. **session.rs**: v2 protocol, `LOCAL_PEEREPID` resolution, server-side registry +
   manifest checks, read-only stance, `session.log`.
4. **Tests**: extend `tests/` with a throwaway-vault (`SECRETS_DIR` +
   `SECRETS_PASSPHRASE`) end-to-end: migrate → get-one → broker-serves-granted-only →
   splice-write → tamper-detection. Then build → **sign** (`./sign.sh`) → install, and
   verify Keychain reachability per `CLAUDE.md` (`has` then `get | wc -c`).

## 10. Open questions

- **OQ1 — broker & human `get`**: §6.3 denies bare `secrets get` during a session.
  Correct by the threat model, but if the ergonomics grate, a `secrets session
  --allow-interactive-get` opt-in flag (still per-key, still logged) is the escape
  hatch. Default stays deny.
- **OQ2 — Argon2id**: v2 is a KDF-migration moment; PBKDF2-600k is kept for continuity
  with the audited core, but if we ever switch to Argon2id, doing it inside the v2
  version byte (a KDF-id byte in the header) would have been free. Decide before
  freezing the header: add `[1] kdf_id` (0x01 = PBKDF2-600k) after the version byte.
  **Recommendation: add it** — one byte buys the whole future.
- **OQ3 — Zig port**: does anything still consume QVLT from the Zig side? If yes, the
  v1 read path there needs a deprecation note.
