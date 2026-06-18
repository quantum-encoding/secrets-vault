# Agent Secret Lifecycle — write-only inbox + batch merge

How an AI coding agent can **generate, use, durably save, and later rotate** secrets
without (a) stopping to ask you mid-run, (b) leaving plaintext in `/tmp` that gets
wiped, or (c) being able to read or silently overwrite your existing credentials.

Companion to `APPROVAL_PROTOCOL.md` (using existing secrets) — this covers the other
half: **creating** them.

---

## 1. The problem

An agent provisions a Cloudflare/AWS token mid-deploy, sets it in the environment,
then the run ends and the value is gone (left in `/tmp`, wiped). Two failures:

- **Security:** the secret sat in plaintext on disk, readable by any later process.
- **Epistemic loss:** the value is gone — you can't repeat the deploy or know what
  you had, forcing manual cloud-console rotation.

Writing it into the vault the normal way needs the AES-256-GCM **master key** →
a Touch ID prompt → interrupts the headless agent. We want **zero-interruption
writes** while keeping reads/overwrites strictly gated.

---

## 2. The write-only inbox (asymmetric, so writes need no tap)

A dedicated **age X25519 keypair** (RFC 9821 / `age` crate — vetted, pure-Rust; do
**not** hand-roll sealing):

| Key | Where | Who can use it |
|---|---|---|
| **recipient** (public, `age1…`) | plaintext `<secrets-dir>/inbox.pub` (0644) | anyone — used only to **seal** |
| **identity** (secret, `AGE-SECRET-KEY-…`) | **biometric Keychain** (UserPresence ACL, same item family as the vault master) | only the owner, only after **Touch ID** |

The asymmetry is the whole point: an agent **seals** a new value with the public
recipient (no tap, no master key), but **cannot open** what it (or anything else)
wrote — opening needs the Keychain identity, which needs a tap. The inbox is a
**one-way drop box**.

> This is the **same Mac sealing keypair** `PHONE_2FA_PROTOCOL.md` §5 needs for
> receiving sealed replies — build it once, use it for both. (It does not exist in
> the Rust code yet; this introduces it.)

### Inbox entry (`<secrets-dir>/inbox.enc`, 0600, JSON-lines)

```jsonc
{ "name": "CLOUDFLARE_TOKEN", "sealed": "<age-armored ciphertext of the value>", "issued": 1750000000 }
```

**Name is plaintext, value is sealed.** Names aren't secret (the manifest lists
them); the value is write-only. So `inbox list` can show *what's pending* with no
tap, while values stay opaque until merge. New-vs-overwrite is **not** stored here —
it's computed at merge against the real vault (the agent can't know it while locked).

---

## 3. Commands

| Command | Touch ID? | Effect |
|---|---|---|
| `secrets inbox init` | no | generate the keypair; identity → Keychain, recipient → `inbox.pub` (idempotent; lazy-runs on first `--inbox` write) |
| `secrets set KEY VAL --inbox` | **no** | seal VAL to `inbox.pub`, append entry. Zero interruption. |
| `secrets gen KEY --inbox` | **no** | generate random → seal → append (value never printed) |
| `secrets inbox list` | no | show pending **names** + count (values stay sealed) |
| `secrets inbox merge` | **one tap** | open the identity, decrypt all entries, show the batch (new/⚠overwrite), merge into `vault.qvlt`, refresh the name index, **wipe `inbox.enc`** |
| `secrets has KEY` / `secrets list --names-only` | no | **BUILT** — existence/name check from the plaintext index, no unlock |

---

## 4. The merge tap *is* the batch approval

Gemini's "write-only inbox" and the batch-group-approval decision are the **same
Touch ID tap** seen from two ends. One merge resolves the whole pending set:

```
3 new secrets pending merge — review:
  • CLOUDFLARE_TOKEN   (new)       → cf-prod
  • DB_PASSWORD        (new)       → metatron
  • STRIPE_KEY    ⚠ OVERWRITE      → billing      ← stomps a known-good value
[ Merge all ]   [ Merge selected ]   [ Cancel ]
```

- **new** keys merge freely.
- **⚠ overwrite** (name already in the vault) is flagged so you can **reject** a key
  that would clobber a working credential — this is the "biometric to overwrite, not
  to enter a new one" rule, enforced at the single merge gate.
- The overwrite check is computed *at merge*, against the just-unlocked vault.

---

## 5. One refinement on Gemini's design — no read-back

Gemini proposed `exec` "dynamically reads the un-merged inbox value for that
execution only." **Drop it.** It punches a hole in the write-only property (the
writing agent could pull freshly-sealed secrets back out before review), and it's
unnecessary: the agent already holds the value it just generated (it set it in
Cloudflare from its own in-memory copy). The inbox exists purely for **durable
safekeeping + future rotation**, never for read-back. Strict one-way drop:

- **Write (new):** no biometric → sealed into inbox. ✅
- **Overwrite/rotate:** allowed *into* the inbox, flagged ⚠ at merge so you can reject. ✅
- **Read:** unchanged — lease/grant (local Touch ID or phone 2FA). ✅
- **Read-back of one's own inbox write:** **not possible** — identity is in the Keychain.

Even a fully-compromised agent can write but can never read or self-approve.

---

## 6. Rotation (the payoff)

```
agent: request new credential from the cloud provider (Cloudflare API)
agent: secrets set CLOUDFLARE_TOKEN <new> --inbox     # sealed, no tap, no interruption
agent: test the new credential from its in-memory copy
…you, later: secrets inbox merge → one tap → review (⚠ OVERWRITE CLOUDFLARE_TOKEN) → merge
```

You never look up the old value, never lose the new one, and the overwrite is gated
behind your review — exactly the safe, scriptable rotation loop.

---

## 7. Build status

- ✅ **`secrets has` / `secrets list --names-only`** — plaintext name index
  (`<secrets-dir>/index.json`, refreshed on every save; names only, never values),
  no unlock.
- ✅ **`age` keypair + Keychain identity** — `age` 0.11 (X25519, `armor` only, no
  default features). Recipient → `inbox.pub` (0644); identity → biometric Keychain
  (`inbox-identity`, UserPresence). Same sealing primitive PHONE_2FA §5 reuses.
- ✅ **`set/gen --inbox`** — seal to `inbox.pub` (no tap, no master), append to
  `inbox.enc` (0600, JSON-lines). Rejects `--gsm`/`--remote` (local-vault only).
- ✅ **`inbox init|list|merge|drop`** — init (tap-free keypair, lazy on first write);
  list (names + new/⚠overwrite from the index, no tap); merge (one tap via a shared
  `read_accounts` auth context → opens identity + master together, classifies
  new-vs-overwrite against the unlocked vault, merges, refreshes the index, keeps
  failed entries); drop (reject one, no tap).
- ✅ **Verified:** seal/open round-trip + write-only property (a different identity
  cannot open) — `cargo test inbox`; `list`/`drop` + new/overwrite tagging end-to-end.

**On-device step still to confirm with a physical tap:** `inbox init` / `set --inbox`
store the identity via `SecItemAdd` (needs the signed binary + keychain entitlement,
same as `unlock`), and `inbox merge` reads identity + master under one shared
`LAContext` (one tap in normal mode; strict mode demands a fresh tap per item by
design). Build + `./sign.sh` + install, then verify the single-tap merge on-device.
