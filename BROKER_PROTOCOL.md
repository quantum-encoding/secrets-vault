# Multi-App Approval Broker — Claim Election

Companion to [`APPROVAL_PROTOCOL.md`](./APPROVAL_PROTOCOL.md). That doc defines the
**CLI ↔ one app** handshake. This doc defines what happens when **several apps**
(AI Conductor, GuardianShield, Cosmic Duck, …) all watch the same handshake dir and
must not all pop a dialog for the same request.

The implementation lives in a shared Swift package — **`SecretsApprovalKit`** — that
every app links. Apps gain biometric-gated secrets consent by adding one dependency;
they do **not** re-implement any vault/keychain/registry crypto (that stays in the
`secrets` CLI, per `APPROVAL_PROTOCOL.md §4/§5`).

---

## 1. The problem

Today one app watches `~/.secrets/pending_approvals/`. If three apps run the same
watcher, a single `<id>.json` request fires **three dialogs**, and three processes
race to shell `secrets authorize` → duplicate work, confusing UX.

## 2. The non-goal (read this — it bounds the whole design)

**Claim election is a UX optimization, NOT a security mechanism.** Safety is already
guaranteed upstream by `APPROVAL_PROTOCOL.md`:

- The only authorization is a **grant in `registry.enc`**, written **only** behind the
  human's biometric tap inside `secrets authorize`.
- The response file is an untrusted "re-check" beep; the CLI re-reads the registry and
  **fails closed** if no grant landed.

So the worst case of a *bad* election — two apps both show a dialog — is merely ugly:
the human taps once in one of them, one idempotent grant is written, the CLI consumes
the first response, the other dialog auto-dismisses when it sees the response file.
**Nothing unsafe happens.** This frees the election to be simple and best-effort rather
than a perfect distributed lock. Do not over-engineer it into a consensus protocol.

## 3. Claim files

Alongside the request `<id>.json`, hosts coordinate through two sidecar files in the
same dir:

| File | Writer | Meaning |
|---|---|---|
| `<id>.json` | CLI | the request (see APPROVAL_PROTOCOL §3) |
| `<id>.claim` | the winning host | "I am rendering this dialog" + heartbeat |
| `<id>_response.json` | the winning host | the re-check beep (APPROVAL_PROTOCOL §4.4) |

`<id>.claim` content:

```json
{
  "host":      "ai-conductor",   // stable host id (see §5 registry)
  "pid":       1234,
  "priority":  10,               // higher = preferred renderer
  "claimed_at": 1718500000,
  "renew_at":   1718500003       // heartbeat: bumped every RENEW_INTERVAL while dialog open
}
```

## 4. The election algorithm

On seeing a new `<id>.json` (and no `<id>_response.json` yet), a host runs:

```
1. backoff = (MAX_PRIORITY - my_priority) * PRIORITY_STEP        // higher priority → shorter wait
   sleep(backoff)                                                 // 0 ms for top host
2. if <id>_response.json now exists      → another host won; ignore.
3. claim = atomic_create(<id>.claim)     // open(O_CREAT|O_EXCL|O_WRONLY, 0600)
      success → I OWN it. Render dialog. Go to §4a.
      EEXIST  → read the existing claim:
                 - renew_at fresh (within CLAIM_TTL)   → owner alive; show passive
                   "Approving in {owner.host}…" toast, do NOT render. Done.
                 - renew_at stale (> CLAIM_TTL old)    → owner presumed dead:
                     unlink the stale claim, GOTO step 3 (one retry).
```

`PRIORITY_STEP = 150 ms`, `CLAIM_TTL = 10 s`, `RENEW_INTERVAL = 3 s`. The backoff is
what makes "where does it fire" deterministic-by-preference: the highest-priority
**running** host claims first; if it isn't running, the next one claims one step later.

### 4a. While the owner's dialog is open

- **Heartbeat:** bump `<id>.claim`'s `renew_at` every `RENEW_INTERVAL`. Stop on dismiss.
- **Foreign response:** if `<id>_response.json` appears while my dialog is open (a
  takeover, or the human authorized out-of-band via terminal `secrets authorize`),
  **dismiss** the dialog — it's already answered.
- **On decision:** exactly as APPROVAL_PROTOCOL §4.4 — shell `secrets authorize …`
  (or nothing, for Deny), then write `<id>_response.json` **only on exit 0** (Deny also
  beeps: no grant → CLI fails closed). Then unlink `<id>.claim`.

## 5. Host registry (priority + identity)

A host's `(id, priority)` is its own constant, not negotiated. Recommended defaults:

| Host id | Priority |
|---|---|
| `ai-conductor` | 30 |
| `guardian-shield` | 20 |
| `cosmic-duck` | 10 |

Rationale: surface consent in the user's primary agent console first; the others are
fallbacks so a request is never stranded just because the top app is closed. A user can
override via `UserDefaults` key `secrets.approval.priority` per app.

## 6. The no-app fallback (unchanged)

If **no** host is running, no claim is ever made, nobody beeps, and the CLI's existing
**30 s timeout → fail closed** kicks in (`APPROVAL_PROTOCOL §6`). The human authorizes
out-of-band in a terminal: `secrets authorize <agent> <project>` (its own Touch ID
system sheet is the tap). So the CLI alone is always a working approver — the apps only
add richer in-the-moment consent UI. **No daemon is required.**

## 7. Phase 2 — cross-device fan-out (designed, NOT built)

Same-Mac routing fans **in** to one dialog (above). Cross-*device* routing fans **out**
(à la Google MFA): push the request to every registered device, first tap wins, the rest
dismiss. Carrier: **ztransfer** (Cloud Run relay + ML-DSA-65 PQ auth) — already in the
toolbox; do not roll a new transport.

`SecretsApprovalKit` reserves the seam now but ships it **disabled**:

```swift
protocol ApprovalTransport {
    /// Forward a request to other registered devices; resolve when one approves.
    func fanOut(_ request: SecretsApprovalRequest) async throws -> SecretsApprovalDecision
}

struct ZTransferFanOutTransport: ApprovalTransport {
    func fanOut(_ request: SecretsApprovalRequest) async throws -> SecretsApprovalDecision {
        throw ApprovalError.notImplemented("cross-device fan-out is phase 2 (ztransfer relay)")
    }
}
```

Config flag `secrets.approval.fanOut` (default **false**). While false the transport is
never invoked. Flip it on before phase 2 lands and it throws the explicit error above —
a planned seam, not a silent gap. Local claim election (§4) is wholly independent of and
unaffected by this flag.

## 8. Implementation map

`SecretsApprovalKit` (new standalone SPM repo, pinned per-app like CosmicDesignKit):

| Piece | Source of truth | Status |
|---|---|---|
| `SecretsApprovalRequest` / `…Decision` | lift from Conductor `SecretsApprovalCenter.swift` | exists |
| `ApprovalWatcher` (FSEvents scan) | Conductor `SecretsApprovalCenter` + `FileWatcher` | exists, extract |
| **`ClaimElection`** (§4) | this doc | **new** |
| `ApprovalConsentView` (themed) | Conductor `SecretsApprovalOverlay.swift` + CosmicDesignKit | exists, extract |
| `secrets authorize` shell-out | Conductor `runProcess` | exists |
| `ApprovalTransport` + ztransfer stub (§7) | this doc | **new (stub)** |

Each app then: add the package, instantiate the center with its host id/priority, mount
the consent view. Conductor's existing `SecretsApprovalCenter`/`Overlay` become thin
shims over the package (or are deleted in favor of it).
