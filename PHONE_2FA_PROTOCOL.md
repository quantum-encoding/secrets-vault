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
> proving the signature came from the genuine, untampered companion app.

```
agent forges an "approved" packet      → no valid SE signature → REJECTED → fail closed
phone owner authenticates + approves   → SE-signed, attested packet → grant written → ALLOWED
```

Everything the relay carries is **request metadata and an approve/deny signal** —
**never secret values**. Secrets stay on the Mac; the `secrets` binary remains the
only thing that writes the encrypted registry, and it does so only after verifying
the phone's signature. The grant in `registry.enc` is still the single source of
truth (the local protocol's `<id>_response.json` "re-check beep" rule applies
verbatim: the response signal is untrusted; the registry grant is the proof).

---

## 2. Actors

| Actor | Role |
|---|---|
| **`secrets` CLI** (Mac) | Requests approval; verifies the signed phone response; writes the grant. The unforgeable write stays here. |
| **aiconductor** (Mac hub) | Watches `~/.secrets/pending_approvals/`, forwards new requests to the relay, and (still) offers the *local* Touch-ID overlay as the same-Mac alternative. |
| **GuardianShield** (Mac, optional) | Sees the `secrets exec` at the kernel level (Endpoint Security); can originate/audit the request and log the out-of-band approval. |
| **Relay** (Cloud Run, `ztransfer`) | Post-quantum, NAT-traversing transport **and** the **APNs provider** (holds the Apple `.p8` push auth key). Forwards request → phone, signal → Mac. Sees only metadata + signed signals. |
| **Companion app** (iOS/iPadOS) | Receives the push, shows the request, runs `LAContext`, signs the decision with its Secure-Enclave key, returns it. |

---

## 3. Why each Apple capability is needed

| Capability | Why | Notes |
|---|---|---|
| **Push Notifications (APNs)** | The *only* way to wake the companion app when it's **closed**. The relay can't wake a dead app; a push can. | Sent by the relay (provider), not the Mac. |
| **Time-Sensitive Notifications** | The approval prompt must pierce Focus/DND. | Easy to enable. |
| **Critical Alerts** | Optional, for "always breaks through silent mode." | **Requires explicit Apple approval** of a special entitlement — don't assume it's granted just because it's listed. |
| **App Attest** | Proves the SE-signed approval came from the **genuine, untampered** companion app on the enrolled device — defeats a cloned/repackaged approver. | One DeviceCheck assertion per approval. |
| **Local Authentication** (`LAContext`) | The actual user check on the phone. **No special entitlement** — built in. | See §6. |
| **Nearby Interaction (UWB)** | *Optional* extra factor: "phone must be physically near the Mac." | Nice-to-have, not required. |
| **Data Protection** | Companion app's local state (enrolled keys, pending request) encrypted at rest. | Standard. |

---

## 4. The flow

```
Mac: secrets exec <project> -- <cmd>   (agent unauthorized for <project>)
  │
  ▼
secrets: write ~/.secrets/pending_approvals/<id>.json   (per APPROVAL_PROTOCOL.md §3)
  │                                                       then poll for the grant
  ▼
aiconductor: FSEvent → POST request to relay  ───────────────►  Relay
  (id, agent, project, command, keys, mac_pubkey, ts)              │ APNs push (Time-Sensitive)
                                                                    ▼
                                                        Companion app (phone) wakes
                                                          shows: "claude wants DATABASE_URL,
                                                            API_KEY from metatron → cargo"
                                                          buttons: Allow once / 15 min / Always / Deny
                                                          │
                                                          ▼  LAContext.deviceOwnerAuthentication
                                                          │  (Face ID / Touch ID / passcode)
                                                          ▼
                                                        Secure Enclave signs:
                                                          { id, decision, session_minutes, device_id,
                                                            nonce, exp }  +  App Attest assertion
                                                          │
  Relay  ◄─────────────────────────────────────────────────┘  (signed approval packet)
  │ forward to Mac (aiconductor long-poll / its own relay channel)
  ▼
aiconductor → secrets: verify-and-authorize <signed packet>
  │
  ▼
secrets: verify( SE signature vs enrolled device pubkey )
         verify( App Attest assertion )
         verify( nonce unused, exp in the future, id matches a live request )
         ── all pass ──►  write grant to registry.enc   (NO local Touch ID needed:
                          the phone biometric WAS the authorization)
         ── any fail ─►  ignore; request times out (30s) → fail closed
  │
  ▼
secrets: write <id>_response.json ("re-check beep") → the blocked exec re-reads
         registry.enc → grant ✓ → inject secrets + spawn child → delete request files
```

If the phone never answers, the original 30 s `pending_approvals` timeout (or a
longer, configurable phone timeout) fires and the exec **fails closed**, with the
local overlay still available as a fallback.

---

## 5. Enrollment (one-time pairing)

Pairing binds one phone to one Mac and exchanges the trust material. It must
itself be a trusted action (do it once, in person, on an unlocked Mac):

1. Mac (aiconductor) shows a **pairing QR** containing: a one-time pairing token,
   the relay endpoint, and the Mac's public key. (Reuse the existing
   remote-control QR pairing path.)
2. Companion app scans it, then:
   - generates a **Secure-Enclave keypair** with an access control of
     `.biometryCurrentSet` + `.privateKeyUsage` (private key never leaves the SE,
     usable only after a successful `LAContext` auth, and **self-invalidated if the
     phone's biometric set changes**);
   - performs **App Attest** key generation + attestation;
   - sends `{ device_id, device_pubkey, attestation, pairing_token }` back via the
     relay.
3. Mac verifies the attestation + pairing token and stores the device record
   (`device_id`, `device_pubkey`) in a local **enrolled-devices** file alongside
   the registry. Multiple devices may be enrolled; any one can approve (or require
   a named device per project — a later refinement).
4. Optional: bind a **UWB proximity** requirement so approvals only succeed when
   the phone is near the Mac.

Revocation: `secrets devices revoke <device_id>` (Touch-ID gated on the Mac)
removes the device record — a lost phone can no longer approve.

---

## 6. Authentication on the device — biometric **or** passcode

The companion app authenticates the human with **`LAContext`** using policy
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

## 7. Message formats

**Request (Mac → relay → phone)** — metadata only, never values:
```json
{
  "id":       "9f3a…",                      // the pending_approvals stem
  "agent":    "claude",
  "project":  "metatron-cloud-prod-v1",
  "command":  "cargo",
  "keys":     ["DATABASE_URL", "API_KEY"],  // names only
  "host":     "director-mbp",
  "issued":   1750000000,
  "nonce":    "…",                          // server-issued, single-use
  "expires":  1750000045                    // request TTL
}
```

**Signed approval (phone → relay → Mac)**:
```json
{
  "id":              "9f3a…",
  "device_id":       "…",
  "decision":        "once | session | always | deny",
  "session_minutes": 2,                      // for once=2 / session=15 / always=null
  "nonce":           "…",                     // echoes the request nonce
  "signed_at":       1750000030,
  "se_signature":    "base64…",               // Secure-Enclave signature over the
                                              // canonical bytes of the above fields
  "app_attest":      "base64…"                // DeviceCheck assertion over the same
}
```

The Mac verifies `se_signature` against the enrolled `device_pubkey`, verifies
`app_attest`, checks `nonce`/`expires`, then maps the decision to the existing CLI:

| decision | CLI write |
|---|---|
| once | `secrets authorize <agent> <project> --session-minutes 2` (effect) |
| session | `… --session-minutes 15` |
| always | `secrets authorize <agent> <project>` |
| deny | write no grant |

…except it writes the grant **directly after verification, without a second local
Touch ID** — the phone biometric already authorized it.

---

## 8. Security properties / guarantees

- **Out-of-band second factor.** Approval requires the physical enrolled phone +
  the owner's biometric/passcode. A same-user Mac adversary has neither. ✅
- **Forgery-proof.** A fabricated approval lacks a valid Secure-Enclave signature
  from an enrolled device → rejected → fail closed. ✅
- **Tamper-proof approver.** App Attest rejects a cloned/modified companion app. ✅
- **Replay-proof.** Single-use server nonce + short `expires` + the request id must
  match a *live* pending request. ✅
- **No secret exposure.** Only names + signals cross the relay; values never leave
  the Mac. The relay is a transport, not a trust anchor. ✅
- **Fail-closed everywhere.** No phone, no answer, bad signature, expired nonce,
  revoked device → no grant → exec denied (with the local overlay as fallback). ✅
- **Biometric-set rotation.** SE key ACL `.biometryCurrentSet` self-invalidates if
  the phone's enrolled fingerprints/face change → a coerced re-enroll can't reuse
  the old key. ✅
- **Lost-phone recovery.** `secrets devices revoke` (Touch-ID gated on the Mac). ✅

---

## 9. Relationship to the local protocol

`APPROVAL_PROTOCOL.md` (local Touch ID) and this phone flow are **two transports
for the same `pending_approvals` request**. aiconductor decides per request (or per
policy) whether to: show the local overlay, push to the phone, or both (require
*both* = true 2-of-2). The CLI side is unchanged except for one addition: a
`verify-and-authorize` path that accepts a signed phone packet in lieu of a local
tap. The registry remains the single source of truth.

---

## 10. Build checklist (what's new vs already built)

- ✅ Transport: `ztransfer` relay (post-quantum, NAT traversal).
- ✅ Request/response protocol: `pending_approvals` + registry-grant-is-truth.
- ✅ Mac signing/verify primitives (ML-DSA-65) — reuse for the relay channel.
- ⛔ **New:** companion iOS app (APNs registration, push handling, `LAContext`,
  Secure-Enclave keygen/sign, App Attest, pairing-QR scan).
- ⛔ **New:** relay as **APNs provider** — send the push (Time-Sensitive) using the
  Apple `.p8` auth key it already holds; route the signed reply back to the Mac.
- ⛔ **New:** `secrets devices enroll|list|revoke` + a `verify-and-authorize`
  entry point that checks the SE signature + App Attest and writes the grant.
- ⛔ **New:** aiconductor wiring — forward `pending_approvals` to the relay and
  long-poll for the signed reply; per-request choice of local / phone / both.

The single entitlement that unlocks the whole thing is **Push Notifications**;
**App Attest** and **Time-Sensitive Notifications** harden it.
