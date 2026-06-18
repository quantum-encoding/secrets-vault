# Agent Secrets — Phone 2FA Approval Protocol (Phase 2)

Authoritative spec for **out-of-band approval on a separate device**: a coding
agent on the Mac requests secrets, and the human approves on their **iPhone/iPad**
with the device's own unlock (Face ID, Touch ID, **or** passcode). The phone is a
second, physically-separate factor — a same-user adversary on the Mac cannot
approve, because they'd need the enrolled phone *and* the owner's face/finger/code.

This extends `APPROVAL_PROTOCOL.md` (the local, same-Mac flow). The two share one
truth: **the approval is real only when a grant exists in the encrypted registry.**
The phone leg just replaces the local Touch-ID tap with a remote, signed,
hardware-attested approval from an enrolled device.

The phone side is **not a new app** — it is a module inside the existing
**Cosmic Duck iOS** multiplatform app, which already carries the phone↔Mac
connectivity foundation (pairing, relay channel, remote control). We add an
approval surface to it, not a fresh binary to install and trust.

---

## 1. Security model (read this first)

The non-negotiable property is unchanged from the local protocol:

> **An agent running as your user must not be able to approve itself.**

In the local flow, the unforgeable boundary is the Secure-Enclave Touch-ID tap on
the Mac. In the phone flow, the boundary **moves to the enrolled phone**:

> The approval is valid only if it is **signed by a biometric-gated key in the
> enrolled device's Secure Enclave** — a key that is (a) created during pairing,
> (b) bound to that one device, (c) usable **only after the phone's owner
> authenticates** (`LAContext`), and (d) accompanied by an **App Attest** assertion
> proving the signature came from the genuine, untampered Cosmic Duck build.

```
agent forges an "approved" packet      → no valid SE signature → REJECTED → fail closed
phone owner authenticates + approves   → SE-signed, attested packet → grant written → ALLOWED
```

Three structural rules tighten the trust boundary beyond a naïve relay design:

1. **Zero-knowledge relay.** The relay **never sees plaintext** project names,
   command strings, or secret key names. Request metadata is sealed end-to-end to
   the enrolled phone's public key; the relay routes an opaque blob by an opaque
   routing ID. It is a dumb post office, not a trust anchor (§3, §7).
2. **Mac-issued challenge.** The single-use challenge nonce is generated **by the
   `secrets` CLI on the Mac**, not by the relay. The relay can never mint, predict,
   or pre-sign a challenge (§4).
3. **No remote "Always."** A phone approval can only grant a **temporary lease**
   (`once`, or a `session` up to **60 minutes** hard-capped). **Permanent** access
   is reachable *only* via a physical local Touch-ID tap on the Mac — a remote
   approver can never install silent persistence (§6).

Everything the relay carries is an **encrypted envelope and an approve/deny
signal** — **never secret values, never plaintext metadata**. Secrets stay on the
Mac; the `secrets` binary remains the only thing that writes the encrypted
registry, and it does so only after verifying the phone's signature *and* its own
outstanding nonce. The grant in `registry.enc` is still the single source of truth
(the local protocol's `<id>_response.json` "re-check beep" rule applies verbatim:
the response signal is untrusted; the registry grant is the proof).

---

## 2. Actors

| Actor | Role |
|---|---|
| **`secrets` CLI** (Mac) | Requests approval; **mints the challenge nonce**; seals request metadata to the phone's pubkey; verifies the signed phone response **against its own outstanding nonce**; writes the grant. The unforgeable write stays here. |
| **aiconductor** (Mac hub) | Signals new requests over the **shared App-Group channel** (§8), forwards the sealed envelope to the relay, and (still) offers the *local* Touch-ID overlay as the same-Mac alternative. |
| **GuardianShield** (Mac, optional) | Sees the `secrets exec` at the kernel level (Endpoint Security); can originate/audit the request and log the out-of-band approval. Shares the App-Group channel. |
| **Relay** (Cloud Run, `ztransfer`) | Post-quantum, NAT-traversing transport **and** the **APNs provider** (holds the Apple `.p8` push auth key). Routes a sealed envelope → phone and a sealed signal → Mac **by opaque routing ID**. Sees no plaintext metadata, no secrets, no project names. |
| **Cosmic Duck iOS** (approval module) | Receives the push, **decrypts** the sealed metadata locally, shows the request, runs `LAContext`, signs the decision with its Secure-Enclave key, seals the reply to the Mac's pubkey, returns it. |

---

## 3. Why each Apple capability is needed

| Capability | Why | Notes |
|---|---|---|
| **Push Notifications (APNs)** | The *only* way to wake Cosmic Duck when it's **closed**. The relay can't wake a dead app; a push can. | Sent by the relay (provider), not the Mac. Push payload is the opaque routing ID + a "you have a request" flag — **no metadata in the push**. |
| **Time-Sensitive Notifications** | The approval prompt must pierce Focus/DND. | Easy to enable. |
| **Critical Alerts** | Optional, for "always breaks through silent mode." | **Requires explicit Apple approval** of a special entitlement — don't assume it's granted just because it's listed. |
| **App Attest** | Proves the SE-signed approval came from the **genuine, untampered** Cosmic Duck build on the enrolled device — defeats a cloned/repackaged approver. | One DeviceCheck assertion per approval. |
| **Local Authentication** (`LAContext`) | The actual user check on the phone. **No special entitlement** — built in. | See §6. |
| **HPKE / Curve25519** | End-to-end sealing of request metadata and reply signal so the relay is zero-knowledge. | `CryptoKit` HPKE (RFC 9180) on iOS 17+, or NaCl `box` (Curve25519 + XSalsa20-Poly1305). |
| **Nearby Interaction (UWB)** | *Optional* extra factor: "phone must be physically near the Mac." | Nice-to-have, not required. |
| **Data Protection** | Cosmic Duck's local state (enrolled keys, pending request) encrypted at rest. | Standard. |

---

## 4. The flow

```
Mac: secrets exec <project> -- <cmd>   (agent unauthorized for <project>)
  │
  ▼
secrets: mint single-use NONCE (CSPRNG, local); record it in the outstanding-nonce
         cache (group container, 0600); seal metadata { agent, project, cmd, keys }
         to the enrolled phone's pubkey  →  ENVELOPE
         write ~/.secrets/pending_approvals/<id>.json  (per APPROVAL_PROTOCOL.md §3)
  │      signal aiconductor over the App-Group socket (§8); then poll for the grant
  ▼
aiconductor: POST { routing_id, envelope } to relay  ───────────►  Relay
             (no plaintext metadata — relay sees opaque blobs)        │ APNs push: { routing_id }
                                                                       ▼   (Time-Sensitive, no metadata)
                                                          Cosmic Duck iOS wakes
                                                            decrypts ENVELOPE locally with its
                                                            private key → shows: "claude wants
                                                            DATABASE_URL, API_KEY from metatron → cargo"
                                                            buttons: Allow once / 15 min / 60 min / Deny
                                                            (no "Always" — see §6)
                                                            │
                                                            ▼  LAContext.deviceOwnerAuthentication
                                                            │  (Face ID / Touch ID / passcode)
                                                            ▼
                                                          Secure Enclave signs:
                                                            { id, decision, session_minutes,
                                                              device_id, nonce, signed_at }
                                                            + App Attest assertion
                                                            → seal reply to Mac's pubkey → REPLY
                                                            │
  Relay  ◄───────────────────────────────────────────────────┘  (sealed reply, by routing_id)
  │ forward to Mac (aiconductor long-poll / its own relay channel)
  ▼
aiconductor → secrets: verify-and-authorize <sealed reply>   (App-Group socket)
  │
  ▼
secrets: open REPLY with Mac private key
         verify( SE signature vs enrolled device pubkey )
         verify( App Attest assertion )
         verify( nonce ∈ outstanding cache, matches this id, unused )  → consume it
         verify( decision ≠ "always"; session_minutes ≤ 60 )
         ── all pass ──►  write temporary-lease grant to registry.enc   (NO local Touch ID:
                          the phone biometric WAS the authorization)
         ── any fail ─►  ignore; request times out → fail closed
  │
  ▼
secrets: write <id>_response.json ("re-check beep") → the blocked exec re-reads
         registry.enc → grant ✓ → inject secrets + spawn child → delete request files
```

If the phone never answers, the original 30 s `pending_approvals` timeout (or a
longer, configurable phone timeout) fires and the exec **fails closed**, with the
local overlay still available as a fallback.

### Nonce handling (rule 2, in detail)

- The nonce is minted by `secrets` with a CSPRNG **on the Mac**. The relay never
  generates, sees in cleartext (it's inside the sealed envelope), or stores it.
- Outstanding nonces live in a **protected local cache** — a 0600 file in the
  shared App-Group container (so the separate `secrets verify-and-authorize`
  invocation can read it), plus in-memory for the live poller. Each entry is keyed
  by request `id` and carries its own short expiry.
- On receipt of a signed reply, `secrets` requires the echoed nonce to **exist,
  match the id, and be unexpired**, then **deletes it** (single-use). A replayed or
  fabricated nonce has no matching cache entry → rejected → fail closed.

---

## 5. Enrollment (one-time pairing)

Pairing binds one phone to one Mac, exchanges **both** public keys (for two-way
sealing), and establishes the opaque routing ID. It must itself be a trusted action
(do it once, in person, on an unlocked Mac):

1. Mac (aiconductor) shows a **pairing QR** containing: a one-time pairing token,
   the relay endpoint, and the **Mac's public key**. (Reuse the existing
   remote-control QR pairing path already in Cosmic Duck.)
2. Cosmic Duck iOS scans it, then:
   - generates a **Secure-Enclave signing keypair** with an access control of
     `.biometryCurrentSet` + `.privateKeyUsage` (private key never leaves the SE,
     usable only after a successful `LAContext` auth, and **self-invalidated if the
     phone's biometric set changes**);
   - generates a **sealing keypair** (Curve25519 / HPKE) for receiving sealed
     metadata;
   - performs **App Attest** key generation + attestation;
   - sends `{ device_id, sign_pubkey, seal_pubkey, attestation, pairing_token }`
     back via the relay.
3. Mac verifies the attestation + pairing token, stores the **Mac's own private
   keys** and the device record (`device_id`, `sign_pubkey`, `seal_pubkey`) in a
   local **enrolled-devices** file alongside the registry, and registers an
   **opaque routing ID** with the relay that maps device→push-token **without
   revealing any identity or project**. Multiple devices may be enrolled; any one
   can approve (or require a named device per project — a later refinement).
4. Optional: bind a **UWB proximity** requirement so approvals only succeed when
   the phone is near the Mac.

Revocation: `secrets devices revoke <device_id>` (Touch-ID gated on the Mac)
removes the device record and tears down its routing ID — a lost phone can no
longer approve.

---

## 6. Decision scope — temporary leases only from the phone (rule 3)

A remote approval is, by construction, made on a device the Mac cannot fully
attest *in the moment of long-term consequence*. So the phone can grant **access
for now**, never **access forever**:

| Phone decision | Lease | CLI effect |
|---|---|---|
| **Allow once** | this invocation only | `secrets authorize <agent> <project> --session-minutes 2` |
| **15 min** | short session | `… --session-minutes 15` |
| **60 min** | max remote session | `… --session-minutes 60` |
| **Deny** | none | write no grant |

- The **`always` decision is removed from the remote protocol entirely.** The
  Cosmic Duck UI offers no "Always" button, and `secrets verify-and-authorize`
  **rejects** any packet whose `decision == "always"` or whose
  `session_minutes > 60` — defense in depth against a tampered client.
- **Permanent / standing** authorization (`secrets authorize <agent> <project>`
  with no TTL) is reachable **only** via a physical **local Touch-ID tap on the
  Mac** (the `APPROVAL_PROTOCOL.md` flow). This prevents a silent persistence
  hijack: even a fully-compromised relay + a coerced single approval can only buy a
  ≤60-minute window, never a durable foothold.

---

## 7. Authentication on the device — biometric **or** passcode

Cosmic Duck authenticates the human with **`LAContext`** using policy
**`.deviceOwnerAuthentication`**:

- Uses **whatever that device has** — Face ID (iPhone X+), Touch ID (SE / older
  iPhones / most iPads), with **no app code branching per modality**.
- **Falls back to the device passcode** automatically if biometrics fail, aren't
  enrolled, or are locked out. This is the "enter your phone unlock code" path —
  the user verifies the request **however they normally unlock their phone**.
- The same `LAContext` evaluation is what gates the Secure-Enclave signing key
  (the key's ACL requires user presence), so authentication and signing are one
  atomic, hardware-enforced step — the app can't sign without a fresh auth.

```swift
let ctx = LAContext()
ctx.localizedReason = "Approve secret access for \(project)"
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, err in
    guard ok else { /* denied / cancelled → send no approval (fail closed) */ return }
    // SE key usage here triggers the same user-presence gate; sign the decision.
}
```

Use `.deviceOwnerAuthenticationWithBiometrics` only if you want to **forbid** the
passcode fallback (max assurance, less convenient). Default to
`.deviceOwnerAuthentication`.

---

## 8. Mac-side signaling — App-Group channel, not file polling

aiconductor, Cosmic Duck (Mac), and GuardianShield **share an Apple App Group**.
For Mac-local signaling between `secrets`, aiconductor, and GuardianShield, prefer
the shared App-Group container over disk polling:

- **Primary:** a **Unix Domain Socket** in the App-Group container
  (`~/Library/Group Containers/<group-id>/secrets-approval.sock`) for
  **zero-disk-write, low-latency** request/response signaling — aiconductor (the
  socket owner) is notified the instant `secrets` has a pending request, and pushes
  the `verify-and-authorize` reply back without a filesystem watcher round-trip.
- **Fallback / durable record:** a **shared directory lock + the `pending_approvals`
  JSON** in the same container. This remains the **source-of-record** so a crash or
  a missed socket event still resolves via the existing FSEvents path. The nonce
  cache (§4) lives here too (0600).
- **Note on the CLI:** `secrets` is a non-sandboxed Rust binary, so it accesses the
  group container **by path** (it can't hold the App-Group *entitlement* the way the
  GUI apps do). That's sufficient for the UDS + lockfile; the entitlement only
  governs the sandboxed GUI apps' access to the same directory. Permissions on the
  socket and cache stay `0600`, owner-only.

The effect: the common case (app running, request pending) is an **in-memory socket
hop with no disk churn**; the file path is retained purely as the durable,
crash-safe fallback and audit record.

---

## 9. Message formats

**Sealed request envelope (Mac → relay → phone)** — relay sees only the outer fields:
```json
{
  "routing_id": "opaque-per-device-handle",   // relay maps this → APNs token; no identity
  "id":         "9f3a…",                        // pending_approvals stem (opaque random)
  "alg":        "HPKE-X25519-SHA256-AES256GCM", // or nacl-box
  "envelope":   "base64…"                       // sealed to the phone's seal_pubkey
}
```

**Sealed plaintext (inside `envelope`, only the phone can open):**
```json
{
  "agent":   "claude",
  "project": "metatron-cloud-prod-v1",
  "command": "cargo",
  "keys":    ["DATABASE_URL", "API_KEY"],       // names only, never values
  "host":    "director-mbp",
  "issued":  1750000000,
  "nonce":   "…",                               // Mac-minted, single-use
  "expires": 1750000045                         // request TTL
}
```

**Sealed approval reply (phone → relay → Mac)** — relay sees only `routing_id` + `id` + blob:
```json
{
  "routing_id": "opaque-per-device-handle",
  "id":         "9f3a…",
  "alg":        "HPKE-X25519-SHA256-AES256GCM",
  "envelope":   "base64…"                        // sealed to the Mac's seal_pubkey
}
```

**Sealed plaintext (inside the reply `envelope`, only the Mac can open):**
```json
{
  "id":              "9f3a…",
  "device_id":       "…",
  "decision":        "once | session | deny",    // NO "always" — rejected if present
  "session_minutes": 15,                          // once=2 / 15 / 60; must be ≤ 60
  "nonce":           "…",                          // echoes the Mac-minted request nonce
  "signed_at":       1750000030,
  "se_signature":    "base64…",                    // Secure-Enclave signature over the
                                                   // canonical bytes of the above fields
  "app_attest":      "base64…"                     // DeviceCheck assertion over the same
}
```

The Mac opens the reply, verifies `se_signature` against the enrolled
`sign_pubkey`, verifies `app_attest`, checks the **outstanding nonce** (exists,
matches `id`, unexpired → consume), enforces the **lease cap** (`decision ≠ always`,
`session_minutes ≤ 60`), then writes the temporary-lease grant **directly after
verification, without a second local Touch ID** — the phone biometric already
authorized it.

---

## 10. Security properties / guarantees

- **Out-of-band second factor.** Approval requires the physical enrolled phone +
  the owner's biometric/passcode. A same-user Mac adversary has neither. ✅
- **Zero-knowledge relay.** The relay never sees project names, commands, key
  names, or secrets — only sealed blobs routed by an opaque ID. Compromising the
  relay leaks **nothing** and forges nothing. ✅
- **Mac-controlled challenge.** The nonce is Mac-minted and Mac-verified against a
  local outstanding-nonce cache; the relay cannot mint or pre-sign challenges. ✅
- **No silent persistence.** The phone can only grant a ≤60-minute lease; permanent
  access requires a physical local Touch-ID tap on the Mac. A coerced or replayed
  remote approval can never install a standing foothold. ✅
- **Forgery-proof.** A fabricated approval lacks a valid Secure-Enclave signature
  from an enrolled device → rejected → fail closed. ✅
- **Tamper-proof approver.** App Attest rejects a cloned/modified Cosmic Duck. ✅
- **Replay-proof.** Single-use Mac nonce (consumed on first use) + short `expires`
  + the request id must match a *live* pending request. ✅
- **No secret exposure.** Values never leave the Mac; metadata never leaves in the
  clear. The relay is a transport, not a trust anchor. ✅
- **Fail-closed everywhere.** No phone, no answer, bad signature, expired/missing
  nonce, `always`/over-cap lease, revoked device → no grant → exec denied (with the
  local overlay as fallback). ✅
- **Biometric-set rotation.** SE key ACL `.biometryCurrentSet` self-invalidates if
  the phone's enrolled fingerprints/face change → a coerced re-enroll can't reuse
  the old key. ✅
- **Lost-phone recovery.** `secrets devices revoke` (Touch-ID gated on the Mac)
  drops the device record and its routing ID. ✅

---

## 11. Relationship to the local protocol

`APPROVAL_PROTOCOL.md` (local Touch ID) and this phone flow are **two transports
for the same `pending_approvals` request**. aiconductor decides per request (or per
policy) whether to: show the local overlay, push to the phone, or both (require
*both* = true 2-of-2). The CLI side is unchanged except for one addition: a
`verify-and-authorize` path that accepts a sealed, signed phone packet in lieu of a
local tap **and can only mint a temporary lease**. The registry remains the single
source of truth, and **permanent grants remain local-Touch-ID-only**.

---

## 12. Build checklist (what's new vs already built)

- ✅ Transport: `ztransfer` relay (post-quantum, NAT traversal).
- ✅ Request/response protocol: `pending_approvals` + registry-grant-is-truth.
- ✅ Mac signing/verify primitives (ML-DSA-65) — reuse for the relay channel.
- ✅ Cosmic Duck iOS app + its phone↔Mac pairing/relay foundation — **extend**, don't recreate.
- ⛔ **New:** Cosmic Duck **approval module** (APNs registration, push handling,
  `LAContext`, Secure-Enclave keygen/sign, App Attest, sealing keypair,
  envelope decrypt, pairing-QR scan reuse).
- ⛔ **New:** relay as **APNs provider** — send the push (Time-Sensitive, metadata-free)
  using the Apple `.p8` auth key it already holds; route the sealed reply back by
  routing ID. **No plaintext metadata ever touches the relay.**
- ⛔ **New:** Mac sealing/opening (HPKE or NaCl box) + the **outstanding-nonce cache**.
- ⛔ **New:** `secrets devices enroll|list|revoke` + a `verify-and-authorize`
  entry point that opens the envelope, checks SE signature + App Attest + nonce,
  **enforces the ≤60-min / no-`always` lease cap**, and writes the grant.
- ⛔ **New:** **App-Group UDS channel** between `secrets`, aiconductor, GuardianShield
  (with the `pending_approvals` lockfile retained as the durable fallback).
- ⛔ **New:** aiconductor wiring — seal/forward envelopes to the relay and long-poll
  for the sealed reply; per-request choice of local / phone / both.

The single entitlement that unlocks the whole thing is **Push Notifications**;
**App Attest**, **Time-Sensitive Notifications**, and end-to-end **HPKE sealing**
harden it.
