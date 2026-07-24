# QVLT v2 — Per-Entry Vault Encryption

**Status: DRAFT v2 — reviewed, not yet implemented.** Companion to
[`BROKER_PROTOCOL.md`](./BROKER_PROTOCOL.md) (approval-dialog election) and
[`APPROVAL_PROTOCOL.md`](./APPROVAL_PROTOCOL.md) (grant handshake). This doc specifies
the successor vault file format and the session-broker protocol change that together
end the "one tap opens the entire jewel room" property of v1.

Revision note: draft v2 incorporates an external design review — Phase 3 write path
moved to a sealed spool (§7), header gains KDF id + flags + external-context MAC
input (§4), peer identity moved to `LOCAL_PEERTOKEN` with honest residual-risk
language (§3.1, §6.2), value lengths bucketed (§4.2), broker passphrase lifetime
ended at derivation (§6.2), rekey/session and rekey/backup interactions specified
(§5.1), migration made explicit-first (§8), and OQ1–OQ3 resolved (§10).

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
(§4.5) plus per-entry AAD binding (§4.4). A second v1 property — a single blob leaks
only *aggregate* size — is preserved approximately via length bucketing (§4.2).

## 2. Goals and non-goals

**Goals**

- G1: `secrets get KEY` decrypts **exactly one** value. All other ciphertexts stay
  ciphertext; no full-vault plaintext ever exists in memory for single-key reads.
- G2: `secrets exec` decrypts exactly the declared key set.
- G3: `secrets set`/`gen`/`delete`/`import` write **without decrypting unrelated
  entries** (§5.2).
- G4: The passphrase's lifetime ends at key derivation. The session broker never
  releases the passphrase or master secret; it serves individual, grant-checked
  values (§6).
- G5: Integrity ≥ v1: per-entry tamper detection, plus detection of entry deletion,
  duplication, reordering, and cross-entry transplants.
- G6: One expensive KDF per open (PBKDF2 600k stays at vault level; per-entry keys are
  cheap HKDF derivations).
- G7: Room for Phase 3 (per-project scope keys / sealed writes, §7) without another
  break of the **vault file** format. (Sealed writes live in a spool *beside* the
  vault file precisely so this holds — see §7.)

**Non-goals**

- Rollback protection against an attacker who replaces the *entire vault file* with an
  older complete copy. v1 doesn't have this either; it requires external state (e.g.
  a monotonic counter in the Keychain). The MAC's external-context input (§4.5) is
  reserved so adding it later is not a format break, but v2 does not ship it.
- Hiding key *names*. Names are non-secret by design throughout the tool
  (`index.json`, `secrets has`, `list --names-only`, `.secrets.toml` manifests).
- Multi-writer concurrency. Writes remain whole-file atomic replace, last-writer-wins,
  same as v1.
- Binary compatibility with the Zig implementation. Not a consideration — nothing on
  the Zig side consumes QVLT; the stale compat claim in `lib.rs`'s module docs is
  removed in this change.

## 3. Threat-model delta

| Scenario | v1 | v2 |
|---|---|---|
| Process memory captured during `get KEY` | all values exposed | one value + master secret* exposed |
| Compromised same-uid process during session window | full passphrase → whole vault, offline, forever | must actively impersonate a granted agent (§3.1); obtains only that agent's declared keys, one per request, only while the broker lives, and leaves a log line per request |
| Attacker edits one entry in the file | detected (blob MAC) | detected (entry GCM tag) |
| Attacker deletes/reorders/duplicates entries | detected (blob MAC) | detected (manifest MAC) |
| Attacker swaps ciphertext between two names | detected (blob MAC) | detected (AAD = name) |
| File-reader learns per-secret sizes | aggregate size only | name + 32-byte-bucketed length (§4.2) |
| Whole-file rollback to older valid vault | undetected | undetected (non-goal; context input reserved, §4.5) |

\* The master secret in memory during a CLI read is unavoidable while the CLI does its
own decryption; the broker path (§6) removes even that from client processes — the
client receives only the requested plaintext value.

### 3.1 Residual risks (stated honestly)

- **Same-uid impersonation.** The broker's caller identity is peer audit token →
  process-ancestry agent resolution. Ancestry is *discretionary*: any same-uid process
  can arrange its parentage under a granted agent's tree or exec the agent binary.
  The uid boundary remains the OS's real trust line, exactly as for ssh-agent. The
  broker therefore does **not** create a new privilege boundary; it narrows the blast
  radius of a same-uid compromise from "whole vault, offline, forever" to "declared
  keys, one at a time, while the broker lives, with an audit trail" — and that
  narrowing, not exclusion, is the claim this spec makes.
- **Local (non-broker) reads hold the master secret** in the client process for the
  duration of the operation. Phase 3 scope keys shrink this.
- **Metadata visibility**: names and bucketed lengths are readable (and, without the
  master secret, *unauthenticated* — §5.4) by anyone with file-read access.
- **Whole-file rollback** — see non-goals.

## 4. File format

Container: magic stays `QVLT`; version byte becomes `0x02`. v1 binaries reading a v2
file fail cleanly with `unsupported vault version: 2` (fail closed, no misparse).

All integers are big-endian, matching v1's serializer.

```text
── Header (28 bytes) ───────────────────────────────────
[4]   Magic            "QVLT"
[1]   Version          0x02
[1]   KDF id           0x01 = PBKDF2-HMAC-SHA256, 600 000 iterations
                       0x02 = reserved (Argon2id)
[2]   Flags            u16, MUST be 0x0000 in this spec.
                       Readers MUST reject any file with an unknown flag bit set.
[16]  Vault salt       KDF salt — stable across saves (§5.1)
[4]   u32 entry count

── Entry record × count (sorted by name, byte-lexicographic, unique) ──
[1]   Key scheme       0x01 = HKDF-from-master (this spec)
                       0x02 = reserved: scope-sealed X25519 (Phase 3, §7)
[2]   u16 name length  1..=513 (§4.1)
[N]   Name             plaintext UTF-8 (§4.1)
[12]  AES-GCM nonce    fresh random per write of this record
[16]  AES-GCM tag
[4]   u32 ct length    = padded plaintext length (§4.2); MUST be a multiple of 32
                       and ≤ 4 + MAX_VALUE_LEN rounded up to the next multiple of 32
[C]   Ciphertext

── Trailer ─────────────────────────────────────────────
[32]  Manifest MAC     HMAC-SHA256(mac_key, file[0 .. len−32] || external_context)
                       external_context = empty in v2 (§4.5)
```

**Structural validation order (normative).** A reader MUST validate, in order:
magic/version/kdf/flags → header length → for each record, that declared lengths stay
in bounds and within the limits above **before allocating buffers based on them** →
that records exactly tile the region between header and trailer → strict name
ordering and uniqueness → manifest MAC → (per accessed entry) GCM tag. Structural
failures and MAC failures are hard errors; nothing about the file is trusted before
the step that validates it.

### 4.1 Names

Grammar (normative): `name = key | project "/" key`, where `key` matches
`is_valid_key` (1..=256 bytes of `[A-Za-z0-9_-]`) and `project` matches
`is_valid_project` (1..=256 bytes of `[A-Za-z0-9_.-]`, no slash). Maximum name length
is therefore **513 bytes** = 256 (project) + 1 (`/`) + 256 (key). At most one `/` may
appear. Readers MUST reject names outside this grammar.

### 4.2 Value padding (length bucketing)

Plaintext record body, before encryption:

```text
[4]  u32 true length          (≤ MAX_VALUE_LEN)
[V]  value bytes
[P]  zero padding             to the next 32-byte multiple of the whole body
```

Writers MUST zero the padding; readers MUST bound-check `true length` against the
decrypted body and MAY ignore padding content (it is authenticated by GCM, so it is
not an oracle). Rationale: v2's per-entry records would otherwise expose exact value
lengths — knowing `AWS_SECRET_ACCESS_KEY` is exactly 40 bytes is confirmation;
knowing a password is 8 characters is targeting information. 32-byte buckets restore
most of v1's aggregate-only property for short secrets at ≤31 bytes overhead; for
large values the bucket is proportionally irrelevant, which is acceptable.

### 4.3 Key derivation

```text
master_secret = KDF(passphrase, vault_salt)                # per header KDF id; 32 B, once per open
entry_key     = HKDF-SHA256(ikm = master_secret, salt = vault_salt,
                            info = "qvlt2:entry:" || u16_be(len(name)) || name)
mac_key       = HKDF-SHA256(ikm = master_secret, salt = vault_salt,
                            info = "qvlt2:manifest")
registry_key  = HKDF-SHA256(ikm = master_secret, salt = vault_salt,
                            info = "qvlt2:registry")       # §6.2
```

Domain separation: the three fixed prefixes are distinct, and the entry info
length-prefixes the name, making entry infos prefix-free among themselves and robust
against any future info string.

The expensive KDF runs once per open — G6. HKDF expansions are per-entry and
effectively free. Immediately after deriving `master_secret`, callers MUST zeroize
the passphrase (G4); `master_secret` and every derived key are held in `Zeroizing`
buffers.

There is no wrapped-DEK table: the per-entry key is a pure derivation from
(master_secret, name). Simpler format, nothing extra to keep consistent, and entry
keys never touch the file.

### 4.4 Entry encryption and AAD binding

```text
ciphertext, tag = AES-256-GCM-Encrypt(entry_key, nonce, aad, padded_body)
aad             = version_byte || scheme_byte || name
```

(name bytes exactly as stored in the record). A record decrypted under the wrong name
fails authentication — ciphertext transplants between names are structurally
impossible, enforced by the AEAD itself rather than by code that remembers to check.
This holds even if a buggy code path skips the manifest MAC.

### 4.5 Manifest MAC

`HMAC-SHA256(mac_key, file[0 .. len−32] || external_context)` — over every byte of
the file except the MAC itself, followed by an **external context** that is the empty
string in v2. Covers the header, all record metadata, **and** all ciphertexts,
restoring v1's whole-file integrity (G5) while still permitting selective decryption:
verifying the MAC requires hashing the file, not decrypting it.

The external context exists so that a future rollback counter (e.g. a Keychain-held
monotonic value) can be mixed into the MAC **without changing the file format**: a
flags bit will declare "context in use" and define its serialization. v2 readers
already reject unknown flag bits, so this upgrade is safe and is not a version bump.

MAC comparison MUST be constant-time (the `hmac` crate's `verify_slice`).

Readers MUST verify the manifest MAC before trusting the entry list (i.e. before
reporting "key not found" or decrypting anything). Verification failure is a hard
error (`DecryptionFailed`-class), same as a v1 tag failure.

### 4.6 Unknown schemes

A reader encountering a scheme byte it does not implement MUST fail closed for that
entry (error on direct access; skip is not allowed for `env`/`list` — those error
too, naming the entry). Phase 3 readers will handle `0x02`; v2-only readers refuse.

## 5. Operation semantics

| Operation | v1 behavior | v2 behavior |
|---|---|---|
| `get KEY` | full decrypt | MAC check → derive 1 key → decrypt 1 record (G1) |
| `exec` | full decrypt, filter | MAC check → decrypt exactly the declared keys (G2) |
| `has` / `list --names-only` | plaintext `index.json` | unchanged; index also rebuildable from the v2 file with no passphrase — but unauthenticated (§5.4) |
| `set` / `gen` / `import` | full decrypt + re-encrypt all | splice records **without decrypting others** (§5.2, G3) |
| `delete` | full decrypt + re-encrypt | remove record, recompute MAC — no decryption |
| `list` (values), `env`, `to_json` | full decrypt | full decrypt (inherently whole-vault; remains discouraged in favor of `exec`) |
| `rekey` (new) | — | full decrypt → fresh salt → re-encrypt all (§5.1) |

### 5.1 Salt lifetime and `rekey`

The vault salt is generated at vault creation and is **stable across saves** — this is
what makes G3 possible: a writer can derive the entry key for the name it's touching
and re-emit every other record's bytes verbatim.

Consequences and rules:

- Entry keys are long-lived per (passphrase, salt, name). Re-encrypting the same name
  many times uses fresh random 96-bit nonces under a fixed key — standard random-nonce
  GCM bounds, negligible risk at CLI write volumes.
- `secrets rekey` performs full decrypt → fresh salt → re-encrypt-all, **including
  `registry.enc`** (its key derives from `master_secret`, §4.3/§6.2), and MUST be
  invoked automatically by any future passphrase-change flow. Recommended after
  revoking a party who may have held the master secret.
- **Rekey vs live session**: a broker holds a `master_secret` derived from the old
  salt; after rekey every broker decryption would fail its MAC check. `rekey`
  therefore **terminates any live session broker first** (the `secrets lock` path:
  `END` + socket unlink), prints that it did so, then proceeds. Silent
  all-requests-fail is not an acceptable failure mode.
- **Rekey vs stale siblings**: the stated use case is revoking a party who may hold
  the old master secret — but that party also trivially holds any old ciphertext.
  `rekey` MUST scan the secrets dir for stale artifacts (`vault.qvlt.v1.bak`, temp
  files, any prior-format sibling), warn loudly naming each one, and offer deletion.
  A rekey that leaves an old-key ciphertext on disk has not revoked anything.

### 5.2 Write path (no-read splice)

`set NEW_KEY` on an existing vault:

1. Read file, run full structural validation + manifest MAC (§4 — hash only, no
   decryption).
2. Derive `entry_key(NEW_KEY)`, pad (§4.2) and encrypt the value, build the record.
3. Re-emit header (count ± 1) + existing records verbatim + new record in sorted
   position; recompute manifest MAC.
4. Atomic replace: write 0600 temp file in `~/.secrets`, fsync the file, rename over
   `vault.qvlt`, then **fsync the directory** (without the directory fsync the rename
   itself can be lost on crash). Refresh `index.json`.

Other entries' plaintexts are never materialized. The same splice serves `delete` and
`import` (batch of records in one rewrite). Note this is stronger than v1 even for
writes: today an agent authorized to *store* a new key transitively reads everything.

### 5.3 Library API sketch (`src/lib.rs`)

`Vault` (decrypt-all) remains for v1 reads and the full-decrypt operations. New:

```rust
pub struct VaultReader { /* parsed header + record index over the raw bytes */ }

impl VaultReader {
    pub fn open(data: &[u8], master: &MasterSecret) -> Result<Self, VaultError>; // §4 validation incl. manifest MAC
    pub fn names(&self) -> impl Iterator<Item = &str>;                          // no decryption
    pub fn decrypt_one(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    pub fn splice(&self, upserts: &[(String, Zeroizing<Vec<u8>>)], deletes: &[String])
        -> Result<Vec<u8>, VaultError>;                                         // §5.2, returns new file bytes
}

pub struct MasterSecret(Zeroizing<[u8; 32]>);   // KDF output; passphrase zeroized after derivation
```

`MasterSecret` replaces passing the passphrase string around `main.rs`: derive once,
zeroize the passphrase, thread the secret. The `cli` feature keeps `lib.rs` dep-free
apart from the existing crypto crates (`hkdf`/`hmac` join `pbkdf2`/`sha2`).

### 5.4 Unauthenticated name reads

Names (and bucketed lengths) are readable from a v2 file without any key material,
which is convenient for rebuilding `index.json`. Normative caveat: such reads are
**unauthenticated** — the manifest MAC needs the master secret. Passphrase-free name
reads are cache/UX material only and MUST NOT gate any security decision (grant
checks, broker responses, etc. always operate on MAC-verified state).

## 6. Session broker v2 — key server, not passphrase dispenser

Transport unchanged: `~/.secrets/session.sock`, 0600 inside the 0700 dir, daemon
started by `secrets session <min>` via the hidden `__session-serve` (passphrase over
stdin pipe), ended by `secrets lock` / lifetime expiry. What changes is the protocol
and the trust model.

### 6.1 Protocol

Requests are a single line; responses are a status line plus optional exact-length
body (values may contain newlines — multi-line values are supported).

```text
GET <project> <key>\n            → OK <len>\n<len bytes>      one decrypted value (true length, unpadded)
                                 → ERR denied\n               no grant for (caller-agent, project)
                                 → ERR unknown-key\n          granted, but key absent (§6.2 ordering)
                                 → ERR scheme\n               entry uses a scheme the broker can't serve
END\n                            → (connection closed)        shut down now (secrets lock)
```

Removed: the v1 `GET` → raw-passphrase response. The passphrase and `master_secret`
never cross the socket in any form — G4.

**Legacy-client handling (normative).** A bare `GET\n` with no arguments is a v1
client. The broker MUST respond with an **empty response and close** — the v1 client
code path (`session::request_passphrase`) treats an empty read as `None` and falls
through to the Touch ID Keychain read, i.e. fails over cleanly instead of misparsing
an error string as a passphrase. Any other malformed request gets `ERR denied`. A v2
broker MUST NOT answer anything with the passphrase.

**Error ordering (normative).** The grant check precedes any vault lookup: a caller
without a grant for `<project>` receives `ERR denied` for **every** key, existing or
not. `ERR unknown-key` is only ever returned to a granted caller (and only for keys
inside its declared set — outside-manifest requests are `ERR denied` too). The broker
must not be an existence oracle for the key namespace.

### 6.2 Server-side enforcement

The v1 broker trusts any same-uid caller with everything. The v2 broker enforces
per-request:

1. **Caller identity**: peer **audit token** via `getsockopt(SOL_LOCAL,
   LOCAL_PEERTOKEN)` (macOS) — the token carries pid *and* pidversion, closing the
   pid-reuse race that `LOCAL_PEEREPID` alone would leave between connect and
   ancestry walk. From the token's (pid, pidversion), run the same process-ancestry
   agent resolution `exec` already uses (`registry::resolve_agent`), **server-side**
   — the caller's claim about who it is is never consulted. (Residual risk: ancestry
   is same-uid-spoofable; see §3.1 — the broker narrows blast radius, it is not a new
   privilege boundary.)
2. **Grant check**: broker requires `grant_for(agent, project)` — the identical check
   `exec` performs, now enforced by the party holding the key material.
3. **Manifest check**: the requested key must appear in the project's declared key set
   (`.secrets.toml` names recorded at authorize time / the scoped `project/KEY`
   namespace), so a granted agent still can't enumerate outside its scope.
4. Derive the one entry key from the *current* vault file (re-read per request — a
   `set` during the session window is picked up naturally), decrypt the one record,
   respond with the true-length value, zeroize.

**Passphrase lifetime in the broker (G4).** At startup the daemon reads the
passphrase from its stdin pipe, derives `master_secret` and `registry_key` (§4.3),
and **zeroizes the passphrase immediately**. It never holds the passphrase for its
lifetime — only derived keys. This requires `registry.enc` to move off
direct-passphrase encryption: **registry v2** uses a raw-key AES-256-GCM container
under `registry_key` (no per-file PBKDF2 — the expensive KDF already happened at the
vault level). Non-broker paths (`exec` fallback, `authorize`, `revoke`) derive the
same way. `secrets migrate` converts the registry container; `rekey` re-encrypts it
(§5.1).

Requests failing any step get their `ERR` per §6.1 and are logged to
`~/.secrets/session.log` (0600; timestamp, agent, project, key **name**, verdict —
never values).

### 6.3 Client fallback ordering (`get_passphrase_prompted` successor)

For **reads**, the client tries: `SECRETS_PASSPHRASE` env (unchanged, discouraged) →
broker `GET` (per-key) → Touch ID Keychain read + local v2 selective decrypt → TTY
prompt → fail closed. For **writes** during a session window: the broker is read-only
by design — writes always take the Keychain/TTY path (a tap). Rationale: the session
exists for unattended `exec` drains; humans initiating writes are present to tap.

Consequence, stated plainly: a plain `secrets get KEY` from a human shell during a
session window is **denied by the broker** (no agent, no grant) and falls through to
Touch ID — one tap, which is not an ergonomic burden. That is intended: the v1
behavior where a session made *every* same-uid read tap-free is exactly the "one
customer sees everyone's jewels" hole. No opt-out flag ships in v2 (OQ1, resolved).

## 7. Phase 3 (reserved): cryptographic multi-tenancy

Not specified here; the format reserves for it. Sketch, so the reservation is honest:

- Scheme `0x02`: entry value sealed to a **per-project X25519 keypair** (the age-style
  machinery `src/inbox.rs` already carries). Record layout for `0x02` prepends a
  scheme-specific key-blob (ephemeral pubkey + wrapped key) to the ciphertext field.
- Project private keys live as separate Keychain items (like `inbox-identity`), so a
  broker/session can be granted the ability to open project A's entries while being
  **cryptographically unable** to open project B's — even if fully compromised.
- **Sealed writes go to a spool, not the vault file.** An unlock-free `secrets set
  --project A` cannot recompute the manifest MAC (that needs `mac_key`, i.e. the
  master secret) — so it MUST NOT touch `vault.qvlt`. Instead it appends an
  age-sealed record to a spool beside the vault (the existing inbox model: seal with
  no tap, merge behind one tap). The next operation that holds the master secret
  folds spooled records into the vault via the normal splice + MAC path and clears
  the spool. The vault file is thus *only ever written under unlock*, its integrity
  story stays uniform, and G7's "no vault-format break" claim holds by construction.
- The whole-file-rollback counter, if adopted, arrives via the reserved
  external-context MAC input + a flags bit (§4.5) — also not a format break.

Phase 3 will still bump the version byte if record layouts change; v2 readers already
fail closed on scheme `0x02` (§4.6) and on unknown flags (§4), so partial upgrades
are safe either way.

## 8. Migration

- **Explicit only, first release**: `secrets migrate` — one unlock, read v1, write v2
  atomically (vault + registry container, §6.2), preserving the v1 file as
  `vault.qvlt.v1.bak` (0600; ciphertext under the same passphrase — delete it once
  confident, and `rekey` will nag about it, §5.1). In the first v2 release, ordinary
  writes to a v1 vault **stay v1** and print a migrate hint: a silently-upgrading
  `set` would brick reads for any older binary sharing the file (dotfiles sync,
  second machine on the previous release). A release later, writes auto-upgrade.
- Reads keep v1 support for at least one release cycle (version-byte dispatch). A v2
  binary must never silently *downgrade* a v2 file.
- The session broker refuses to start (`secrets session`) against a v1 vault: print
  the migrate hint and exit non-zero, rather than reviving the passphrase-dispenser
  behavior.
- Docs to update in the same change: `CLAUDE.md` (§first-run), `README.md` §5,
  `AGENT_SECRET_LIFECYCLE.md`, and removal of the stale "binary-compatible with the
  Zig version" claim from `lib.rs` module docs.

## 9. Implementation order

1. **lib.rs**: v2 serializer/parser with the §4 validation order, `MasterSecret`,
   `VaultReader` (open / decrypt_one / splice), padding, `rekey` core; unit tests
   incl. transplant, deletion, reorder, duplicate-name, truncation, bounds-overflow
   (allocation-order), unknown-scheme, unknown-flag, and padding vectors.
2. **main.rs**: thread `MasterSecret` (zeroize passphrase at derivation); route
   `get`/`exec` through `decrypt_one`, writes through `splice`; `migrate` + `rekey`
   commands (incl. session-termination + stale-sibling warnings); v1 read fallback.
3. **registry.rs**: raw-key container under `registry_key`; migrate + rekey paths.
4. **session.rs**: v2 protocol incl. legacy-`GET` empty-close, `LOCAL_PEERTOKEN`
   resolution, server-side grant/manifest checks with normative error ordering,
   read-only stance, `session.log`.
5. **Tests**: extend `tests/` with a throwaway-vault (`SECRETS_DIR` +
   `SECRETS_PASSPHRASE`) end-to-end: migrate → get-one → broker serves granted key /
   denies ungranted uniformly / empty-closes v1 `GET` → splice-write →
   tamper-detection. Then build → **sign** (`./sign.sh`) → install, and verify
   Keychain reachability per `CLAUDE.md` (`has` then `get | wc -c`).

## 10. Resolved questions (was: open questions)

- **OQ1 — broker & human `get`: deny, no escape hatch.** The §6.3 fallback chain
  makes a human's `get` cost exactly one Touch ID tap — not an ergonomic burden worth
  a flag that weakens the story. Revisit only if real usage complains.
- **OQ2 — KDF agility: yes, and more.** The header carries a KDF id byte and a flags
  field, and the manifest MAC takes an external-context input (empty in v2) — so an
  Argon2id switch, feature bits, and a rollback counter are all non-breaking (§4,
  §4.5).
- **OQ3 — Zig port: not relevant.** Migration policy (§8) is driven purely by
  *same-binary-family* version skew (synced dotfiles, second machine on an older
  release), not cross-language compat.
