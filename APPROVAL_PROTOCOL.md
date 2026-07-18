# Agent Secrets — Approval Protocol

Authoritative spec for the real-time approval handshake between **`secrets`** (the
Rust CLI) and **`aiconductor`** (the SwiftUI desktop app). The CLI side is
implemented and adversarially tested; this document is the contract the
aiconductor side builds against.

---

## 1. The security model (read this first)

When an agent (Claude, Grok, …) runs `secrets exec <project> -- <cmd>` and is **not**
already authorized for `<project>`, the CLI requests real-time approval from the
human via aiconductor. The non-negotiable property:

> **An agent running as your user must not be able to approve itself.**

The naive design — the CLI polls for a `*_response.json` and trusts its contents —
is **broken**: a same-user agent can watch the directory and write its own
`{"decision":"always"}` before aiconductor does, bypassing the human entirely.
(Don't rely on filesystem perms or an App Group container to stop this — a
non-sandboxed `npm postinstall` writes user-owned paths directly.)

**Therefore the response file is an UNTRUSTED "re-check" signal.** The approval is
real **only if a grant now exists in the encrypted registry** (`registry.enc`,
AES-256-GCM), which only aiconductor — gated by the human's biometric — can write.
The CLI ignores the response file's contents and re-reads the registry; no grant →
**fail closed**.

```
agent forges {"decision":"always"}  →  CLI re-reads registry  →  no grant  →  DENIED
human taps approve in aiconductor    →  grant written to registry.enc  →  CLI sees it  →  ALLOWED
```

The hard, unforgeable boundary is the **Secure-Enclave biometric tap** that writes
the grant. The popup is informed consent; the tap is the authorization.

---

## 2. Filesystem layout

| Purpose | Path | Notes |
|---|---|---|
| Approval handshake dir | `~/.secrets/pending_approvals/` | Override: `$SECRETS_APPROVAL_DIR`. Plain same-user dir — **no App Group entitlement / provisioning profile.** Created `0700`. |
| Encrypted registry | `<secrets-dir>/registry.enc` | `<secrets-dir>` = `$SECRETS_DIR` or `~/.config/secrets`. AES-256-GCM (QVLT). The source of truth for grants. |

Note the two dirs differ by default (`~/.secrets/` vs `~/.config/secrets/`). aiconductor
only needs the **handshake dir** unless it writes the registry natively (§5, not recommended).

---

## 3. The request file (CLI → aiconductor)

When approval is needed, the CLI writes `<id>.json` into the handshake dir, where
`<id>` is a 32-char hex (16 random bytes):

```json
{
  "id":      "9f3a…",                       // also the filename stem
  "agent":   "claude",                      // resolved calling agent
  "project": "metatron-cloud-prod-v1",      // target project
  "command": "cargo",                       // child command (argv[0])
  "keys":    ["DATABASE_URL", "API_KEY"],   // requested secret names
  "reason":  "deploy staging build"         // OPTIONAL — `secrets exec --reason`;
                                            // omitted from the wire when not given
}
```

`reason` is a human justification shown on the aiconductor consent slab (and folded
into the OS Touch ID sheet's reason line) so the approver sees *why*, not just a bare
biometric scan. It is display-only intent, never an authorization input — the grant
still comes only from the human's biometric via the encrypted registry. Absent ⇒ the
prompt still shows agent/project/command/keys.

The CLI then blocks, polling every **100 ms** for `<id>_response.json`, up to a
**30 s** timeout (override `$SECRETS_APPROVAL_TIMEOUT_SECS`). On timeout it deletes
its request and fails closed.

---

## 4. aiconductor responsibilities (the recommended path: shell out)

**Do not reimplement the QVLT/PBKDF2/AES-GCM crypto in Swift.** Byte-matching the
registry format across two languages is where subtle, dangerous bugs live. Instead,
delegate the grant write to the `secrets` binary, which is the single source of
truth.

1. **Watch** `~/.secrets/pending_approvals/` (FSEvents / `DispatchSource`) for new
   `*.json` files that are **not** `*_response.json`.
2. **Parse** the request (`id`, `agent`, `project`, `command`, `keys`).
3. **Present** the themed glass-slab dialog, e.g.
   `🔐  {agent} wants {keys} from {project} → {command}`
   with four buttons, **labeled with their real security cost**:
   - `Allow once` — Touch ID each time; most secure
   - `Allow this session` — 15 min; any local process can reuse during the window
   - `Always allow` — permanent; un-gated until revoked
   - `Deny` — fail closed
4. **On click**, run the installed `secrets` binary (its own biometric prompt fires
   here — that is the unforgeable tap), then write the signal file:

   | Button | Command to run |
   |---|---|
   | Allow once | `secrets authorize <agent> <project> --session-minutes 2` |
   | Allow this session | `secrets authorize <agent> <project> --session-minutes 15` |
   | Always allow | `secrets authorize <agent> <project>` |
   | Deny | *(run nothing — write no grant)* |

   Then **always** write `<id>_response.json` (any content — it's just the "re-check"
   beep) and dismiss the dialog.

   > **"Allow once"** maps to a short (2-min) session grant because the CLI verifies
   > via *a grant in the registry* — so "once" still needs one. Two minutes is
   > practically single-build; exactly-once consume-and-delete is a later refinement.

5. **Locate the binary** — aiconductor needs the absolute `secrets` path
   (e.g. `~/.local/bin/secrets` or `/usr/local/bin/secrets`). This is the one
   coordination detail to pin per install.

### Sequence

```
CLI: write <id>.json ───────────────────────────────► aiconductor: FSEvent
CLI: poll for <id>_response.json                       aiconductor: show dialog
                                                       human: click "Allow this session"
                                                       aiconductor: run `secrets authorize … --session-minutes 15`
                                                       secrets: Touch ID → write grant → registry.enc
                                                       aiconductor: write <id>_response.json
CLI: response seen → re-read registry.enc → grant ✓ → inject + spawn child
CLI: delete <id>.json and <id>_response.json
```

---

## 5. Alternative: native registry write (NOT recommended)

If aiconductor must write the grant itself (no shell-out), it needs:
- The shared keychain entitlement `keychain-access-groups = VLK8CVU5H3.io.quantumencoding.secrets`
  to read the master passphrase (item: service `io.quantumencoding.secrets`,
  account `vault-master`, `UserPresence` ACL) via `LAContext`.
- A **byte-exact** reimplementation of the registry container:
  - QVLT layout: `"QVLT"` + `0x01` + 16-byte salt + 12-byte nonce + 16-byte GCM tag + ciphertext.
  - Key = PBKDF2-HMAC-SHA256(passphrase, salt, **600 000** iters) → 32 bytes.
  - AES-256-GCM, empty AAD; plaintext = the registry JSON.
- Registry JSON shape:
  ```json
  { "projects": { … },
    "grants": { "<agent>": { "<project>": { "scope": "always" } } } }
  // session scope: { "scope": { "session": { "expires": <unix_secs> } } }
  ```

This is strictly more work and more risk than §4. Prefer the shell-out.

---

## 6. Edge cases / guarantees

- **Forged response** (agent writes `<id>_response.json`, no grant) → CLI re-reads
  registry → no grant → **fail closed**. ✅ (tested)
- **aiconductor not running** → 30 s timeout → fail closed, with a hint to
  `secrets authorize <agent> <project>` out-of-band. ✅ (tested)
- **Deny** → aiconductor writes no grant, only the signal → CLI sees no grant →
  fail closed. ✅
- **Pre-authorized agent** (existing valid grant) → CLI proceeds **without** any
  request/popup, and **without** aiconductor running. The handshake is only for
  *new* authorizations.
- **Phase 2 / iOS**: the phone can't share this local dir. aiconductor (Mac) is the
  hub; it forwards the same request over the ztransfer relay to the phone / Cosmic
  Duck for out-of-band-on-a-separate-device approval. Same protocol, second transport.

---

## 7. CLI commands aiconductor invokes

```
secrets authorize <agent> <project>                       # permanent grant (Touch ID)
secrets authorize <agent> <project> --session-minutes <N>  # timed grant (Touch ID)
secrets revoke    <agent> <project>                       # remove a grant (Touch ID)
secrets list-projects                                     # inspect grants (Touch ID)
```

All are biometric-gated and write the encrypted registry. aiconductor never needs
to touch the registry file directly when using these.

---

## 8. Network-connection approvals (GuardianShield interactive firewall)

The **same** request/response handshake + glass-slab consent UI (SecretsApprovalKit)
is reused by GuardianShield's Network Extension to turn silent blocking into a
human-in-the-loop firewall. The request carries a `type` discriminator; absent ⇒
`secrets` (so §3 stays valid). Network requests set `"type": "network_connection"`.

### Why a different directory

The NE (`NEFilterDataProvider`) is **strictly sandboxed** — it cannot write
`~/.secrets/`. It writes into the shared **App Group container**:

```
~/Library/Group Containers/group.io.quantumencoding.workspace/pending_approvals/
```

Both GuardianShield (writer) and the approver app (reader) hold that App-Group
entitlement, so the dir is reachable by both. The approver's `SecretsApprovalCenter`
must watch this dir **in addition to** `~/.secrets/` (point it via the same
`$SECRETS_APPROVAL_DIR` mechanism, or watch both).

### Request file — `<id>.json` (NE → app)

```jsonc
{
  "id":          "<uuid>",            // also the filename stem; keys the paused flow
  "type":        "network_connection",
  "agent":       "Brave Browser",     // resolved process name
  "destination": "youtube.com",       // target host (or IP if no DNS name)
  "port":        443
}
```

### Response file — `<id>_response.json` (app → NE)

Unlike the secrets beep (whose content is ignored — the registry is the truth),
this content **IS authoritative**: there's no registry behind a firewall verdict, so
the NE resumes the paused flow from it.

```jsonc
{ "id": "<uuid>", "decision": "allow_once" }   // | "allow_always" | "deny"
```

- `allow_once` → `resumeFlow(flow, with: .allow())` for this flow only.
- `allow_always` → `.allow()` **and** add `destination` to the NE's dynamic allowlist
  (so subsequent flows to that host bypass the prompt entirely).
- `deny` → `resumeFlow(flow, with: .drop())`.

### NE-side contract (the non-obvious bits)

- **Defer, don't drop:** `handleNewFlow` returns `NEFilterNewFlowVerdict.pause()` and
  stores the `NEFilterFlow` keyed by `id`. Resume **on the same serial queue** as
  `handleNewFlow` to avoid the "Ignoring resume command for flow … which does not
  exist" race.
- **UDP is on a clock:** a paused **UDP** flow (QUIC / HTTP-3 = UDP 443) is
  **auto-dropped by the system after 10 s**. So the prompt timeout must be < 10 s and
  default to `deny` (fail-closed) on expiry.
- **Cache hard:** only the *first* flow to a new `(process, host)` pauses; decisions
  cache so a single web page's dozens of hosts don't each prompt.
- **Backstop:** if the approver app isn't running (no response), the NE must fail to a
  safe default after timeout and a drop-rate **circuit breaker** must auto-revert to
  audit — never black-hole connectivity (the "left it in enforce and nuked the
  internet" failure mode).
- **Trust boundary:** the response lives in the App-Group container (not the
  world-writable `~/.secrets/`), but it is still a *same-user* channel — acceptable for
  a firewall (Little Snitch trusts the GUI choice too) given the fail-closed default.
