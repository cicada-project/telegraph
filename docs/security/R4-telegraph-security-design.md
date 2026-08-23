---
evidence_id: R4-telegraph-security-design-20260823
gate: R4
claim_ids:
  - C-R4-001
  - C-R4-002
  - C-R4-003
  - C-R4-004
  - C-R4-005
  - C-R4-006
  - C-R4-007
  - C-R4-008
  - C-R4-009
  - C-R4-010
classification: independent-review
source_type: mixed-primary
source_locator: "docs/security/R4-telegraph-security-design.md"
source_version_or_commit: "Claim-level fixed tags, commits, and URLs are recorded in Section 16."
accessed_at_utc: "2026-08-23T08:08:38Z"
observed_environment: "Telegraph research/design documents; no implementation environment"
reproduction:
  command: "not applicable: design report; no implementation command run"
  exit_code: null
  result_summary: "Design review and claim-level evidence ledger; implementation not observed"
artifact_sha256: null
status: corroborated
reviewer: independent-subagent-r4-security-review
reviewed_at_utc: "2026-08-23T08:08:38Z"
design_gate: accept_with_conditions
implementation_authorization: blocked_reject
security_claim: E2EE_not_claimed
---

# Telegraph R4 security design

**Status:** Draft
**Review:** Design gate accepted with conditions
**Security claim:** E2EE not claimed
**Implementation gate:** blocked/reject; conditions remain open
**Scope:** research/design only; no implementation, deployment, or cryptographic code

## Independent review disposition

- **Reviewer:** `independent-subagent-r4-security-review`
- **Reviewed at (UTC):** `2026-08-23T08:08:38Z`
- **Design gate:** accept with conditions
- **Implementation authorization:** blocked/reject; this disposition does not authorize implementation
- **Security claim:** E2EE not claimed

The reviewer accepted the design gate conditionally. The following conditions are not closed and remain implementation blockers:

1. Approve the exact protocol profile, implementation library, license, external-use/support posture, pinned commit, and dependency audit.
2. Approve an ADR for the exact transcript encoding, domain separation, handshake-derived confirmation key, and confirmation MAC construction.
3. Obtain product approval for authenticated-channel safety-code UX, including manual/telephone/independent-QR comparison and the complete transcript-hash QR.
4. Approve the three receipt meanings, encryption/idempotency rules, message/pairing TTLs, user-code format, and rate-limit/expiry/deletion defaults.
5. Define and review the secure rollback anchor, crash semantics, device revocation, identity rotation, and per-channel repair policy.
6. Execute and pass the positive/negative automated acceptance vectors in Section 13; the vectors are design requirements, not evidence that implementation exists.

## 1. Decision summary

The proposed R4 protocol is a Signal-style asynchronous secure-messaging profile:

- device-level long-term identity key per OS user/Telegraph daemon;
- opaque local thread endpoints, with the real Codex thread ID kept inside the client;
- one independent channel, bootstrap/prekey state, and Double Ratchet state for every thread-to-thread pair;
- relay-mediated discovery and store-and-forward only;
- relay-generated high-entropy `device_code` for client polling and a separate short-lived human `user_code` entered by the second client;
- activation only after both device identity keys, endpoint commitments, channel ID, prekeys, protocol version, and pairing transcript produce the same safety code and both sides confirm it;
- transport acknowledgements kept separate from encrypted end-to-end receipts.

The recommendation is conditional. Selecting a concrete Signal/PQXDH implementation, license, supported API, and maintenance posture is an implementation-blocking decision. In particular, the official `signalapp/libsignal` repository is AGPLv3 and says that use outside Signal is unsupported; it cannot be selected for Telegraph without an explicit legal, support, and maintenance decision. See the fixed [libsignal v0.101.0 source](https://github.com/signalapp/libsignal/tree/v0.101.0) (accessed 2026-08-23; release short commit `b056faa`, full commit must be resolved before implementation).

The only conditional permissive implementation candidate found in this review is [vodozemac 0.10.0](https://github.com/matrix-org/vodozemac/tree/0.10.0), an Apache-2.0 pure-Rust Olm/Double Ratchet implementation. It is not Signal X3DH/PQXDH/Sesame and must not be represented as equivalent. If the product requires exact Signal/PQXDH semantics, R4 remains deferred until a supported, permissively licensed implementation is approved.

This document does not authorize implementation or claim that Telegraph currently provides E2EE.

## 2. Product and repository boundaries

The local contracts remain authoritative. The Cicada baseline files are repository-level contracts outside the `telegraph/` subtree; they are referenced from Telegraph as `../docs/...`, not as Telegraph-owned documents:

- `../docs/00-product-baseline.md:25-31`: no Master/Subagent hierarchy and no assumption that a hierarchy is needed.
- `../docs/01-stage-1-plugin-contracts.md:45-77`: MVP is exactly two equal Codex CLI peers, text messages, peer text as conversation input, and local message/receipt/sequence/failure audit.
- `../docs/01-stage-1-plugin-contracts.md:64-69`: no attachments, files, commands, group chat, external chat, or other harnesses in the Codex MVP.
- `../docs/01-stage-1-plugin-contracts.md:79-83`: public incoming-message injection must not be assumed before its public semantics and security are verified.
- `../docs/04-research-gates.md:1-3,41-43`: research gates precede implementation; R4 follows a viable R1 Codex route.

The repository may eventually contain both a Telegraph client and a central relay server. This document defines only their security boundary. It does not add implementation code, a generic IR, Web3, a group protocol, remote TUI attachment, or local transport optimization.

The first central deployment is referred to only as `relay-a`. Repository documentation must not contain its physical IP address. Physical co-location, the same network, a different machine, or a future central cluster does not change the cryptographic trust boundary.

## 3. Architecture and trust boundary

```text
Codex CLI + Telegraph client A
  - device identity and secure storage
  - opaque local thread endpoints
  - per-channel prekey/ratchet state
  - plaintext handoff to its own Codex thread
                |
                | RelayTransport: discovery, mailbox, transport ack
                v
        central relay: relay-a
                ^
                |
Codex CLI + Telegraph client B
```

Both Codex CLIs are Telegraph clients. The relay is a central rendezvous and mailbox service, not a cryptographic endpoint.

### 3.1 Relay compromise model

Assume the relay is malicious or fully compromised. It may:

- read endpoint/mailbox IDs, timing, direction, envelope size, delivery state, and other transport metadata;
- issue, suppress, race, or misroute discovery codes;
- substitute or withhold public prekey material;
- delete, delay, reorder, duplicate, truncate, or replay ciphertexts;
- forge transport acknowledgements and deny service.

It must not be able to recover message plaintext, identity private keys, prekey private keys, ratchet state, or a valid encrypted end-to-end receipt. A malicious relay can still cause pairing or delivery failure. Availability is not guaranteed by this design.

The client and its local Codex App Server are a plaintext endpoint: the companion sees decrypted peer text in order to pass it to the local Codex thread. R4 does not claim protection against a fully compromised OS, process, or unlocked endpoint.

### 3.2 Narrow future interfaces

Future adapters may implement the following responsibilities without changing the security model.

`RelayTransport` is limited to:

- `create_pairing_intent` and pairing status polling;
- `claim_pairing` and cancellation;
- public prekey-bundle discovery and replacement;
- opaque envelope submission and mailbox polling;
- transport-level acknowledgement;
- TTL, size, quota, abuse rate limiting, and mailbox state.

`MailboxStore` stores only opaque routing and transport data:

- opaque mailbox ID;
- opaque `delivery_id`;
- protocol/version framing needed for routing and quota checks;
- ciphertext envelope and size;
- expiry and transport status.

Neither interface accepts plaintext, decrypts, generates keys, opens a session, interprets Codex content, or injects into a thread. A future central cluster or Web3 adapter is deferred and must preserve this narrow opaque-envelope/mailbox/ack contract. No Web3 implementation and no generic IR are part of R4.

## 4. Assets, attackers, assumptions, and non-goals

### 4.1 Assets

- Peer text, Codex replies, and their authenticity/integrity.
- Device identity private keys, public identity keys, signed prekeys, one-time prekeys, and channel bootstrap state.
- Per-channel Double Ratchet state, epochs, sequence state, skipped-message keys, and replay state.
- Pairing intent, discovery codes, endpoint bindings, channel IDs, safety code, and transcript.
- Ciphertexts, encrypted receipts, transport acknowledgements, and local audit records.
- Real Codex thread IDs, thread-to-endpoint mappings, workspace context, and local permissions.
- Availability, delivery ordering, duplicate suppression, revocation, and recovery state.

### 4.2 Attackers

- Curious or malicious relay and network observer.
- Active pairing MITM or unknown-key-share attacker.
- Malicious peer with a valid but revoked or stale identity.
- Endpoint/storage attacker capable of rollback, backup restoration, or key extraction.
- Fully compromised peer process, OS user, daemon, or local dependency.
- Abuse attacker attempting code enumeration, pairing races, mailbox flooding, or resource exhaustion.

### 4.3 Trust assumptions

- Device identity private keys remain inside client-controlled secure storage.
- Users perform the required safety-code/fingerprint confirmation, or a future separately approved authenticated channel does so.
- The local companion and local Codex endpoint are trusted to handle plaintext; the relay is not.
- Clients persist channel state atomically enough to detect rollback or fail closed.
- The selected protocol implementation is independently reviewed and its license/support terms are accepted.

### 4.4 Explicit non-goals

- No protection against an endpoint that is fully compromised while handling plaintext.
- No metadata anonymity, traffic-analysis resistance, cover traffic, or hidden participation.
- No group membership, parent/child hierarchy, automatic hand-off, attachments, files, commands, or remote execution.
- No arbitrary existing interactive-TUI attachment.
- No WebSocket/remote-control security claim.
- No Web3, blockchain, wallet, token, or generic cross-harness protocol.
- No claim of post-quantum mutual authentication beyond the selected protocol's documented properties.
- No public non-repudiation or publicly verifiable conversation transcript.

## 5. Identity and channel model

### 5.1 Device identity

Each OS user/Telegraph daemon owns one long-term device identity:

```text
DeviceIdentity {
  device_identity_id       // opaque local identifier
  identity_public_key
  identity_private_key     // secure storage only
  status                   // active | rotating | retired | revoked
  created_at
  rotated_at
  revoked_at
  signed_prekey_state
  one_time_prekey_pool_state
}
```

The exact key type and library profile are blocking implementation decisions. The device identity is not a Codex thread identity.

### 5.2 Opaque thread endpoints

Each local Codex thread may register a local endpoint:

```text
ThreadEndpoint {
  endpoint_handle          // random 128-bit opaque handle
  local_codex_thread_id    // never leaves the client
  workspace_binding        // local authorization only; never uploaded or hashed
  endpoint_commitment      // DS-SHA256(endpoint_handle || pairing_nonce)
  pairing_nonce            // fresh random 128-bit value per pairing intent
  device_identity_id
  status
}
```

`endpoint_handle` is generated randomly with 128 bits of entropy. For each pairing, `pairing_nonce` is a fresh random 128-bit value and:

```text
endpoint_commitment = SHA-256(
  "telegraph.endpoint-commitment/v1" || endpoint_handle || pairing_nonce
)
```

The quoted prefix is the domain separator; the real Codex thread ID, workspace ID/name/path, or SDK session record is never an input to this hash and never leaves the client. Workspace authorization is a purely local policy check. The server may see an opaque endpoint/mailbox reference and may correlate it with a device identity or traffic pattern.

### 5.3 Per-thread channel

Every thread-to-thread pair creates a new channel:

```text
ChannelState {
  channel_id
  local_endpoint_handle
  remote_device_identity_key
  remote_endpoint_commitment
  session_id
  ratchet_epoch
  send_receive_sequence_state
  bounded_skipped_key_state
  status                    // pending | active | rotation_required | repair_required | closed | revoked
}
```

The `channel_id`, session bootstrap, prekey use, Double Ratchet state, and audit sequence are independent for every pair. One thread may have several simultaneous channels to local or remote peer threads.

## 6. Pairing and discovery state machine

### 6.1 Code distinction

The protocol deliberately distinguishes two relay-generated values:

- `device_code`: high-entropy opaque value returned to the initiating client. The initiator polls with it; the user does not type it. It is a short-lived rendezvous capability, not an identity proof.
- `user_code`: short-lived human-friendly code displayed for the second client to enter. The proposed default is a 50-bit Crockford Base32 value, for discovery only; it has strict rate limits and a small attempt budget.

The relay may know both values. Neither value alone authenticates the peer or activates a channel.

### 6.2 Recommended state machine

```text
IDLE
  -> INTENT_CREATED
  -> DEVICE_CODE_ISSUED
  -> USER_CODE_DISPLAYED
  -> USER_CODE_CLAIMED
  -> KEY_MATERIAL_EXCHANGED
  -> TRANSCRIPT_READY
  -> A_CONFIRMED and/or B_CONFIRMED
  -> BOTH_CONFIRMED
  -> CODES_CONSUMED
  -> CHANNEL_ACTIVE

Any incomplete state -> EXPIRED | CANCELLED | ABORTED | BURNED
Active channel      -> REPAIR_REQUIRED | CLOSED | REVOKED
```

1. Client A creates an intent for a local opaque endpoint and uploads a signed/committed intent containing the endpoint commitment, protocol profile, expiration, and nonce.
2. Relay creates and stores commitments for the high-entropy `device_code` and short `user_code`, returning the `device_code` only to A and the `user_code` for A to display.
3. A polls pairing status using `device_code`; it never asks the user to type this value.
4. Client B enters `user_code`. Relay performs an atomic claim and returns only a discovery handle. Pairing is not active.
5. A and B exchange the public device identity keys, endpoint commitments, channel ID, signed prekey/one-time prekey material or hashes, protocol profile, and transcript nonces.
6. Both derive the same transcript hash and short human safety code.
7. Both clients display the safety code/fingerprint. Both must compare it over an authenticated channel independent of the relay: face-to-face, a telephone call, or an independently transferred QR. Clicking “confirm” in the relay UI alone does not count. The exact UX is a product approval item.
8. Each side derives a handshake confirmation key and sends a MAC over the canonical transcript plus its role and confirmation decision. Each client verifies the peer MAC locally. Only then does the relay consume both codes and do clients create the channel ratchet state.
9. Any mismatch, timeout, cancel, attempt exhaustion, or protocol downgrade aborts the intent and burns the codes.

### 6.3 Code lifecycle requirements

- Codes are generated from a cryptographically secure random source; the high-entropy `device_code` is at least 128 bits and is used by A for polling, not manual entry.
- Proposed defaults, pending product approval, are: pairing intent TTL 10 minutes; `user_code` TTL 10 minutes; `user_code` 50-bit Crockford Base32; a five-attempt claim/rate-limit budget per code; per-client/per-origin/global rate limits; exponential backoff; jitter; and uniform error responses.
- The short `user_code` is not relied on for cryptographic strength. The attempt budget and rate limits are defenses against enumeration, not peer authentication.
- Relay stores commitments and state rather than relying on persistent plaintext code storage.
- `CLAIMED`, `CONSUMED`, `EXPIRED`, `CANCELLED`, and `BURNED` codes cannot be reused.
- Concurrent claims are atomic: one wins and other claimants do not learn detailed state.
- Cancellation invalidates all pending handles and pre-confirmation transcript state.
- A new device or a re-pair always creates a new intent, transcript, channel ID, and ratchet state.

### 6.4 Why a server-generated code is not identity authentication

The code proves only knowledge of a relay-issued rendezvous value. A compromised relay could route A to attacker M, substitute public keys, race a claim, or suppress the intended peer. If the product simply trusts a relay identity directory, it loses independent detection of key substitution, unknown-key-share, malicious rotation, and relay impersonation. Confidentiality against the relay might remain, but peer authenticity would no longer be cryptographically independent of that relay.

The MVP therefore uses `user_code`/`device_code` only for discovery and requires both device identity keys and safety-code/fingerprint confirmation.

Relay deletion is an explicit state transition: after both authenticated confirmations, the intent is atomically marked `CONSUMED`, codes and pre-confirmation material are deleted or cryptographically tombstoned, and a retry of the final confirmation returns the same idempotent result without reopening the intent. On relay crash, an intent remains either pending or consumed according to the durable transaction record; clients retry idempotently and never infer activation from a transport timeout. Expiry, cancellation, failed confirmation, or attempt exhaustion deletes/tombstones all code material and quarantines any late claim.

## 7. Transcript, safety code, and protocol binding

The pairing transcript contains at least:

The transcript is encoded using RFC 8949 deterministic CBOR (canonical/deterministic map-key ordering and definite lengths), then domain-separated before hashing:

```text
transcript_cbor = RFC8949-deterministic-CBOR({
  protocol_profile_and_version,
  relay_alias,                    // relay-a; no physical IP
  intent_id, claim_id,
  device_code_commitment,
  user_code_commitment,
  A_device_identity_public_key,
  B_device_identity_public_key,
  A_endpoint_commitment,
  B_endpoint_commitment,
  channel_id,
  prekey_bundle_hashes,
  role_and_direction,
  pairing_expiration,
  A_nonce, B_nonce,
})
transcript_hash = SHA-256("telegraph.pairing-transcript/v1" || transcript_cbor)
```

The transcript must bind both roles and directions, both device identity keys, both endpoint commitments, channel ID, prekeys, protocol/version, code commitments, and both nonces. Real thread/workspace IDs are absent. The exact CBOR field labels and profile version are implementation ADR items, but RFC 8949 deterministic encoding and the domain separator are hard requirements.

The displayed safety code is derived from `transcript_hash` and must display at least 64 bits. An independently transferred QR must contain the complete 256-bit `transcript_hash` (and enough context to identify the pairing), not only the short display code. The safety code is not a key and is not accepted as the sole authentication input. Safety-code length, formatting, QR layout, and accessibility are product approval items.

After the selected handshake derives a confirmation key, each side computes a MAC over `transcript_hash`, its role, direction, and confirmation decision. Each client verifies the peer MAC locally before marking the peer confirmed. The relay cannot manufacture a valid confirmation without the handshake-derived key.

The selected X3DH/PQXDH profile must bind identity and prekey material to the channel transcript and associated data. The Double Ratchet session ID, epoch, channel ID, and endpoint binding must be checked on every inbound envelope. A channel or endpoint mismatch fails closed and cannot inject text into a different Codex thread.

Primary protocol references:

- [X3DH](https://signal.org/docs/specifications/x3dh/) — asynchronous identity/prekey bootstrap, fingerprint authentication, replay and key-deletion considerations.
- [PQXDH, Revision 3](https://signal.org/docs/specifications/pqxdh/) — asynchronous post-quantum bootstrap, prekey bundles, identity binding, replay, server trust, and key compromise considerations.
- [Double Ratchet, Revision 4](https://signal.org/docs/specifications/doubleratchet/) — per-message keys, DH ratchet, out-of-order messages, secure deletion, and compromise recovery.
- [Sesame](https://signal.org/docs/specifications/sesame/) — asynchronous mailbox/session management, retry and delivery-receipt concepts.

## 8. Candidate comparison

### A. Signal-style X3DH/PQXDH + Double Ratchet + Sesame

Pairing uses the relay code only for discovery; device identity keys and independent human safety confirmation provide identity binding. Device-level signed/one-time prekeys bootstrap each independent channel; the resulting session feeds a separate Double Ratchet state.

It supports offline initial delivery, per-message key evolution, bounded skipped-key handling, rekeying, and a documented place for retry/receipt state. It still requires product-level revocation, endpoint compromise recovery, metadata policy, and exact thread-binding rules. This is the recommended protocol family, subject to the blocking implementation/license/support decision in Section 9.

### B. Conditional permissive implementation: vodozemac 0.10.0 (Olm-style)

[vodozemac 0.10.0](https://github.com/matrix-org/vodozemac/tree/0.10.0) is an Apache-2.0 pure-Rust implementation of Olm and Megolm. Its official [Cargo metadata](https://github.com/matrix-org/vodozemac/blob/0.10.0/Cargo.toml) records version `0.10.0`, Apache-2.0, Rust 1.85, and edition 2024. Its [Account API](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Account.html) exposes device identity and one-time/fallback key management; its [Session API](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Session.html) implements asynchronous Olm Double Ratchet sessions. The official README records one Least Authority audit with no significant findings, but the audit scope and Telegraph-specific integration remain subject to independent review.

This is the only conditional permissive candidate selected by R4 library research. It can map one Telegraph device to one Account and one thread-to-thread pair to one Session, but it does not supply Telegraph pairing, endpoint commitments, device-code UX, relay mailbox semantics, receipts, or Codex thread binding. It is not X3DH, PQXDH, or Sesame, and must not be described as Signal-equivalent. The v0.10.0 release contains breaking API changes, so Telegraph must hide it behind an adapter and pin the full release commit (the official page exposes short commit `bb39ec6`). Default `libolm-compat` behavior and secure state persistence require explicit review.

R4 may proceed with this candidate only if product accepts an Olm-style classical protocol and an independent ADR/review approves the profile. It remains **implementation blocked** until the full commit, dependency licenses, Linux builds, persistence tests, and audit report are reviewed.

### C. Noise handshake plus application-defined session rekey

The [Noise Protocol Framework](https://noiseprotocol.org/noise.html) defines static/ephemeral handshake patterns, transcript hashing, transport cipher state, `Rekey()`, and application responsibilities for out-of-order/replay handling.

Noise can fit an online pairing or a pre-established static-key flow. Pairing would still need device-code rendezvous, independent safety confirmation, identity/key continuity, and transcript binding. Rotation would require an application-defined handshake/rekey policy; Noise does not select per-channel recovery semantics. Replay, out-of-order delivery, offline prekey bootstrap, mailbox retry, and message/receipt idempotency would all be Telegraph responsibilities. Receipts would need a separate authenticated application message, and audit would need to record handshake/epoch state without key material. It does not by itself provide X3DH/PQXDH-style asynchronous one-time prekeys, mailbox session management, or Double Ratchet-style post-compromise recovery. It is a complete handshake framework, but too easy to under-specify for this MVP; **rejected/deferred**.

### D. HPKE or libsodium sealed-box per-message envelope

The [HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and [libsodium sealed-box documentation](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) describe one-shot public-key encryption. Sealed boxes use a fresh ephemeral key per message but do not authenticate the sender identity. HPKE application embedding leaves message order, replay, loss, and metadata handling to the application and does not provide recipient-compromise forward secrecy.

Pairing would still need identity signatures or PAKE/independent confirmation; rotation would require replacing recipient keys and defining revocation. Offline delivery is easy as independent envelopes, but there is no built-in session ordering, replay window, duplicate semantics, post-compromise recovery, or mailbox/receipt protocol. Receipts need a separate authenticated key and audit policy. This is a useful negative baseline: relay plaintext confidentiality can pass while identity continuity, replay, order, post-compromise recovery, and session revocation fail. It is **rejected as the MVP protocol**.

### E. OpenMLS/RFC 9420

[OpenMLS](https://github.com/openmls/openmls/tree/47dbede) is MIT and implements [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html). It provides group credentials, epochs, ratchet trees, commits, and application messages. A two-member group is possible, but it is not a direct pairwise Double Ratchet replacement. Pairing, device-code discovery, endpoint binding, delivery service, offline welcome/commit handling, receipts, and audit remain application responsibilities. Its state and epoch semantics are materially more complex than two independent peer channels, and the official security advisory for v0.7.0 demonstrates that persistence behavior must be treated as a security boundary. It is **deferred for a future group requirement**, not selected for the two-peer MVP.

| Property | Signal/PQXDH + DR + Sesame | vodozemac/Olm DR | Noise + app rekey | HPKE/sealed box | OpenMLS/MLS |
|---|---|---|---|---|---|
| Asynchronous initial delivery | Native design target | Account/prekey/session support; mailbox adapter required | Extra application design | Simple independent messages | Welcome/commit delivery service required |
| Device identity and fingerprint | Required | Account identity; Telegraph confirmation required | Application binding | Extra Auth/signature required | MLS credentials; application binding |
| Per-message key evolution | Yes | Yes, Olm Double Ratchet | Policy-dependent | No session ratchet | Epoch/tree ratchets, not pairwise DR |
| Out-of-order/replay | Protocol state plus app bounds | Session state plus app bounds | App responsibility | App responsibility | Epoch/group state plus app policy |
| Post-compromise recovery | Ratchet-dependent, documented | Olm-style; profile/review required | Re-handshake/app policy | Not provided | MLS update/epoch semantics |
| Offline retry/receipt model | Sesame reference | Custom Telegraph layer | Custom | Custom | Custom delivery service |
| Relay plaintext resistance | Yes, if profile/library correct | Candidate only; not implemented/reviewed | Yes, if profile/library correct | Yes, if profile/library correct | Yes, if profile/library correct |
| Implementation/license risk | libsignal currently blocking | Apache-2.0; API/dependency review required | Framework composition risk | Weak protocol properties | MIT but group complexity |
| R4 status | **Recommended family, conditional** | **Conditional alternative** | Defer | Rejected baseline | Defer |

## 9. Implementation-blocking library and license decision

The protocol family recommendation does not select a library.

The official [libsignal repository](https://github.com/signalapp/libsignal) states that it is used by official Signal clients and servers, that use outside Signal is unsupported, and that APIs/bridge layers may change without notice. The same repository states that it is licensed under AGPLv3. Therefore:

- `libsignal` cannot be treated as an automatically usable Telegraph dependency;
- legal review must decide whether AGPLv3 is compatible with the intended client/relay distribution;
- engineering must verify whether unsupported external use is acceptable;
- the team must choose a supported, maintained implementation or obtain an explicit support/licensing path;
- no implementation starts while this decision is unresolved.

The fixed release evidence reviewed for this decision is [libsignal v0.101.0](https://github.com/signalapp/libsignal/releases/tag/v0.101.0), short verified commit `b056faa`. The full commit, transitive dependency licenses, and external-use terms still require gate-time verification. The official build instructions also require Rust nightly plus Clang/libclang, CMake, Make, protoc, Python, and multiple language bridge toolchains, increasing cross-Linux packaging risk.

The conditional alternative is [vodozemac 0.10.0](https://github.com/matrix-org/vodozemac/releases/tag/0.10.0), short verified commit `bb39ec6`, Apache-2.0, pure Rust, Rust 1.85/edition 2024. The official README records one Least Authority audit with no significant findings, but this is not an audit of Telegraph's pairing, endpoint binding, relay, persistence, or receipt design. The release has breaking API changes; a Telegraph adapter and full immutable commit are mandatory. Linux CI must cover at least x86_64 GNU, x86_64 musl, and aarch64 GNU, plus crash/restart and secure state storage. Dependency license closure and the default `libolm-compat` feature require an explicit review.

OpenMLS stable evidence is [v0.8.1](https://github.com/openmls/openmls/releases), short verified commit `47dbede`, MIT. It is deferred because its RFC 9420 group/epoch/tree model adds delivery and persistence complexity without providing a direct pairwise Double Ratchet path. The official security advisory for `0.7.0`/`0.7.1` must be included in the patch policy; no Telegraph-specific audit evidence was found.

The choice between classical X3DH and PQXDH, the exact Double Ratchet profile, key types, serialization, and library version must be recorded in a later approved ADR. No custom cryptographic composition is permitted.

## 10. Offline delivery, ordering, replay, and failure semantics

### 10.1 Envelope separation

The outer relay envelope contains only opaque routing/transport fields:

```text
mailbox_id
delivery_id
protocol_version
opaque_ciphertext
size
ttl
```

The encrypted inner payload contains:

```text
channel_id
message_id
ratchet_epoch
sequence
message_kind
peer_text_or_control_payload
thread-binding commitment
```

The actual Codex thread ID is never in either relay-visible layer.

### 10.2 Offline and retry

Proposed defaults, pending product approval, are: relay ciphertext message TTL 7 days; pairing intent and `user_code` TTL 10 minutes; five invalid `user_code` claims before burn. The relay deletion process must be idempotent and crash-safe: mark expiry/consumption durably before deleting payload rows, retry deletion after a crash, and quarantine late retries rather than reopening a mailbox.

- Relay may retain ciphertext until the proposed 7-day TTL or an explicitly approved mailbox policy expires.
- A transport retry is idempotent by `delivery_id`.
- A plaintext delivery is idempotent by inner `message_id` and ratchet state.
- A recipient that cannot decrypt because of rollback, missing state, or channel repair does not accept plaintext; it emits a bounded resync/re-pair signal according to the selected profile.
- Relay loss or timeout is retryable; identity mismatch, AEAD failure, revoked key, stale epoch, invalid transcript, and downgrade are terminal or require re-pair.

### 10.3 Ordering and replay

Double Ratchet sequence and bounded skipped-key state handle allowed out-of-order delivery. The application still enforces:

- maximum skipped keys and maximum gap;
- duplicate suppression by inner message ID;
- stale epoch rejection;
- no second Codex input for a replayed valid ciphertext;
- bounded memory and CPU under replay/flood attacks.

### 10.4 Transport ack versus E2E receipt

`TransportAck` is relay-supplied and untrusted. It means only that the relay accepted, stored, fetched, or deleted an opaque envelope.

The receipt contract has three distinct, separately encrypted, channel-authenticated levels. Each has a unique idempotency key, a monotonic per-channel receipt sequence, and a referenced inner `message_id`; a receiver never moves a receipt state backward:

1. `decrypted`: the recipient authenticated and decrypted the message.
2. `codex_accepted`: the local client accepted the peer text as input to the intended local Codex endpoint.
3. `turn_completed`: the local Codex turn reached the product-defined completion condition.

The product must approve which levels are emitted and retained. A later receipt may supersede an earlier level for the same message, but a duplicate or older receipt is a no-op. The relay cannot forge any of these levels because it sees only transport acknowledgements and ciphertext.

Only a valid channel-authenticated E2E receipt can advance local E2E delivery state. A forged or replayed receipt must fail authentication or be ignored as a duplicate.

### 10.5 Atomic persistence and crash semantics

For outbound data, the client must atomically persist the new ratchet state, deduplication/sequence state, and ciphertext envelope before sending it to the relay. A crash after persistence but before send is retried with the same `delivery_id`; a crash after send does not roll the ratchet state backward.

For inbound data, the client must authenticate/decrypt, atomically persist the ratchet advancement and deduplication decision, and only then hand plaintext to the local Codex endpoint. A crash before injection leaves a retryable local acceptance record; it must not cause a second Codex input. A normal crash with incomplete or inconsistent state fails closed and requires controlled repair. A full-disk rollback that defeats a secure rollback anchor is treated as endpoint compromise and is outside the ordinary crash guarantee; it triggers device/channel recovery rather than silent continuation.

### 10.6 One-time prekey consumption and exhaustion

One-time prekey claim, use, deletion, and durable inventory update must be one atomic operation. A crash or duplicate claim must not allow the same one-time prekey to bootstrap two channels. Inventory is monitored and replenished before exhaustion. If the pool is exhausted or atomic consumption cannot be proven, a new pairing fails closed; it must not silently downgrade to a reusable prekey or a no-identity handshake.

## 11. Audit privacy and metadata

Default local audit records:

- opaque device, endpoint, channel, message, and delivery identifiers;
- transcript/safety-code confirmation result;
- ratchet epoch and sequence status;
- transport status and E2E receipt status separately;
- failure class, retry count, and timestamps;
- keyed or otherwise privacy-reviewed digests rather than plaintext.

Audit must not write private keys, prekey private keys, ratchet keys, raw device/user codes, or unredacted plaintext by default. A digest can still leak equality or dictionary information and needs a product retention decision.

The relay may learn endpoint/device correlation, timing, ciphertext length, direction, mailbox activity, code-attempt volume, and traffic frequency. R4 does not claim metadata hiding.

## 12. Rotation, revocation, and compromise blast radius

### 12.1 Ordinary prekey rotation

Rotating signed prekeys or replenishing one-time prekeys is device-level maintenance. It does not silently rebind existing channels to a new identity and should not require every active channel to be recreated.

### 12.2 Device identity rotation

Because one device identity covers all endpoints and channels, identity rotation affects every channel on that device:

1. Generate the new identity key in secure storage.
2. Mark the old identity `rotating`; do not silently replace it in channel state.
3. Mark every active channel `rotation_required`.
4. Perform a separate channel repair/re-pair for each peer thread, creating a new transcript, channel ID, prekey bootstrap, and ratchet state.
5. Confirm a new safety code per channel.
6. Atomically mark the old channel `closed`, delete its ratchet/channel keys after the approved transition window, and reject or quarantine all late messages and receipts for that channel.

If compromise is suspected, do not trust the old identity to authorize a silent transition. Revoke the old device identity, create a new pairing intent, and re-pair each channel with a new fingerprint.

### 12.3 Channel-only repair

A channel-specific failure, peer key change, rollback, or repair affects only that channel. It creates a new channel ID and ratchet state for that thread pair; it does not rotate the device identity or other channels.

The old channel is closed, its keys are deleted according to the approved retention window, and late ciphertexts/receipts are rejected or quarantined. A channel-specific repair must not silently revive old state.

### 12.4 Device compromise

An attacker with the device identity private key can impersonate the device to new peers and may affect multiple channels. An attacker with one channel's ratchet state should not automatically obtain other channels' plaintext. Endpoint compromise while plaintext is present remains outside scope. Revoke the device identity and perform per-channel re-pair after recovery.

## 13. Automated acceptance vectors

### Positive vectors

1. One OS user/daemon has one device identity and two or more opaque endpoints; the relay never receives either real Codex thread ID.
2. One endpoint creates two independent channels; channel A's state cannot decrypt channel B's ciphertext.
3. A creates an intent; relay returns a high-entropy `device_code` for A polling and a separate short `user_code` for B input.
4. A never needs to manually type `device_code`; polling reports claim, mismatch, cancel, expiry, and completion states.
5. B claims with a valid `user_code`; no channel activates before both safety-code confirmations.
6. Matching device identity keys, endpoint commitments, channel ID, prekey hashes, version, and transcript produce the same safety code.
7. A valid asynchronous initial message can be stored while B is offline and later bootstraps the selected channel profile.
8. Messages delivered out of order within limits are accepted once; duplicate `delivery_id` or `message_id` does not produce a second Codex input.
9. Relay transport ack changes only transport state; a valid encrypted E2E receipt changes E2E state.
10. Planned device identity rotation marks all device channels for repair; each repaired channel receives a new channel ID and safety code.
11. Channel-only repair does not rotate unrelated channels.
12. Local audit correlates endpoint, channel, message, transport, E2E receipt, sequence, and failure status without raw private keys or codes.
13. Safety-code comparison succeeds only when both users compare through an authenticated channel independent of relay-a; relay UI confirmation alone is rejected.
14. The same transcript fields encoded with RFC 8949 deterministic CBOR produce the same domain-separated 256-bit transcript hash on both clients; the safety display is at least 64 bits and an independent QR carries the full hash.
15. Confirmation MACs derived from the handshake confirmation key verify locally on both sides; a relay cannot submit a valid confirmation MAC.
16. Endpoint handles and pairing nonces are independently random 128-bit values; the endpoint commitment matches the domain-separated SHA-256 formula and contains no real thread/workspace ID.
17. The three encrypted receipt levels (`decrypted`, `codex_accepted`, `turn_completed`) are monotonic and idempotent; transport ack cannot advance them.
18. Proposed defaults are observable and configurable only through an approved product decision: relay message TTL 7 days, pairing/user-code TTL 10 minutes, 50-bit Crockford user code, five failed claims.
19. Outbound crash tests show state+ciphertext persistence before send; inbound crash tests show ratchet/dedup persistence before Codex injection.
20. One-time prekey consumption is atomic, and an exhausted pool causes fail-closed pairing rather than silent downgrade.

### Negative vectors

1. A relay swaps either identity key, endpoint commitment, channel ID, prekey hash, version, or transcript field; safety code differs and activation fails.
2. A correct `user_code` without identity/fingerprint confirmation cannot activate a channel or inject text.
3. Expired, cancelled, consumed, burned, or already-claimed codes cannot be reused.
4. Concurrent claims are atomic; losing claimants receive no detailed code-state oracle.
5. Repeated invalid `user_code` attempts trigger rate limiting, backoff, and code burn without revealing whether a code exists.
6. Relay-forged transport ack does not produce `e2e_decrypted` or `codex_accepted`.
7. Relay-forged, modified, or replayed E2E receipt fails channel authentication or is idempotently ignored.
8. Ciphertext mutation, stale epoch, invalid prekey signature, revoked identity, transcript mismatch, or downgrade never produces plaintext.
9. A message for endpoint A cannot be injected into endpoint B even when the same device owns both.
10. Restoring an old channel snapshot causes rollback detection or controlled repair; it does not silently reuse message keys.
11. Old device identity after rotation/revocation cannot create a new channel or silently continue as the new identity.
12. Physical co-location or shared network does not bypass identity confirmation.
13. Relay-visible metadata is present in the test observation, while plaintext and valid E2E receipts remain unavailable to relay.
14. The narrow relay interface has no plaintext/decrypt/key-generation/session-opening operation.
15. A safety code shown only in relay UI, a short-code collision, an altered CBOR field/order, or a missing QR transcript hash prevents activation.
16. A relay-substituted endpoint handle, nonce, code commitment, identity key, prekey, role, direction, or protocol version causes transcript/MAC failure.
17. Receipt replay, receipt downgrade, or a transport ack presented as an E2E receipt cannot advance local state.
18. Relay expiry, consumed-code deletion, crash/retry, and late message deletion are idempotent; expired or burned pairing material cannot reopen.
19. Full-disk rollback without a valid secure anchor fails closed as endpoint compromise; ordinary crash with incomplete state never silently continues.
20. Duplicate one-time-prekey claims, zero inventory, or failed atomic consumption prevent pairing and never fall back to reusable/no-identity material.

## 14. Product decisions still required

- Classical X3DH versus PQXDH profile, and the exact supported implementation.
- Legal/support decision for any candidate library, especially `libsignal` AGPLv3 and unsupported external use.
- Safety-code display length (minimum 64 bits), wording, full-hash QR/manual confirmation UX, independent authenticated channel, and what counts as a human confirmation.
- Proposed defaults pending product approval: relay message TTL 7 days; pairing/user-code TTL 10 minutes; 50-bit Crockford Base32 `user_code`; five failed claims; rate limits, lockout, and audit retention.
- Whether workspace binding is only local policy or a transcript-bound security context.
- Whether E2E receipt means decrypt, Codex acceptance, or completed turn.
- Audit retention, digest construction, plaintext policy, and deletion behavior.
- Device rotation grace period and whether any old-key transition certificate is permitted; silent rotation is not permitted for MVP.
- Relay metadata, mailbox TTL, quotas, and abuse handling.

## 15. Claims prohibited before implementation and review

Do not claim:

- Telegraph has implemented, provides, or completed E2EE; this document is a design draft with implementation blocked and review conditions still open.
- A server-generated `device_code` or `user_code` alone authenticates a peer.
- The relay cannot observe metadata or cause denial of service.
- A transport ack proves decryption, Codex acceptance, or completion.
- Any arbitrary existing TUI session is attached or externally injectable.
- `libsignal` is an approved Telegraph dependency; its official repository says AGPLv3 and unsupported external use.
- Device identity rotation can silently update all channels.
- Channel-only repair has no effect on the affected channel's old state.
- Web3, local transport, group semantics, or a generic IR are implemented.
- Independent security review has passed.

## 16. Evidence ledger

Evidence was opened from official pages/files, not search-result summaries, on 2026-08-23. Repository evidence uses a release tag or immutable commit locator; no unversioned-branch claim is used. The independent review disposition corroborates C-R4-001..009; C-R4-010 remains an unverified design inference, and the implementation conditions above remain open.

```yaml
status: corroborated
reviewer_id: independent-subagent-r4-security-review
reviewed_at_utc: "2026-08-23T08:08:38Z"
design_gate: accept_with_conditions
implementation_authorization: blocked_reject
security_claim: E2EE_not_claimed
access_date: 2026-08-23
claims:
  - id: C-R4-001
    kind: local-contract
    statement: "Cicada baseline requires exactly two equal Codex CLI peers and research gates before implementation."
    source_locators:
      - "../docs/00-product-baseline.md:25-31 (repository-level contract outside telegraph/)"
      - "../docs/01-stage-1-plugin-contracts.md:45-83 (repository-level contract outside telegraph/)"
      - "../docs/04-research-gates.md:1-3,41-43 (repository-level contract outside telegraph/)"
    status: corroborated

  - id: C-R4-002
    kind: protocol
    statement: "Signal X3DH/PQXDH, Double Ratchet, and Sesame define the reference asynchronous identity/prekey/ratchet/session-management properties."
    source_locators:
      - "https://signal.org/docs/specifications/x3dh/"
      - "https://signal.org/docs/specifications/pqxdh/"
      - "https://signal.org/docs/specifications/doubleratchet/"
      - "https://signal.org/docs/specifications/sesame/"
    status: corroborated

  - id: C-R4-003
    kind: license-support
    statement: "libsignal v0.101.0 is AGPLv3, official use outside Signal is unsupported, and APIs/bridges may change."
    source_locators:
      - "https://github.com/signalapp/libsignal/releases/tag/v0.101.0 (short verified commit b056faa)"
      - "https://github.com/signalapp/libsignal/blob/v0.101.0/README.md:202-214,362-367"
    status: corroborated

  - id: C-R4-004
    kind: implementation-candidate
    statement: "vodozemac 0.10.0 is an Apache-2.0 pure-Rust Olm/Double Ratchet implementation with device Account and Session APIs; it is not Signal/PQXDH."
    source_locators:
      - "https://github.com/matrix-org/vodozemac/releases/tag/0.10.0 (short verified commit bb39ec6)"
      - "https://github.com/matrix-org/vodozemac/blob/0.10.0/Cargo.toml:5-12,36-44"
      - "https://github.com/matrix-org/vodozemac/blob/0.10.0/README.md:21-28,50-56"
      - "https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Account.html"
      - "https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Session.html"
    status: corroborated

  - id: C-R4-005
    kind: audit
    statement: "vodozemac README links one Least Authority audit reporting no significant findings; scope and Telegraph integration are not thereby audited."
    source_locators:
      - "https://github.com/matrix-org/vodozemac/blob/0.10.0/README.md:50-56"
      - "https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf"
    status: corroborated

  - id: C-R4-006
    kind: implementation-candidate
    statement: "OpenMLS v0.8.1 is MIT and implements RFC 9420 MLS; it is a group/epoch/tree protocol and is deferred for two-peer MVP."
    source_locators:
      - "https://github.com/openmls/openmls/commit/47dbede (release v0.8.1)"
      - "https://github.com/openmls/openmls/blob/47dbede/LICENSE"
      - "https://github.com/openmls/openmls/blob/47dbede/README.md"
      - "https://www.rfc-editor.org/rfc/rfc9420.html"
    status: corroborated

  - id: C-R4-007
    kind: security-history
    statement: "OpenMLS security advisory affected 0.7.0 and lists 0.7.1 as patched; persistence is a security boundary."
    source_locators:
      - "https://github.com/openmls/openmls/security/advisories/GHSA-qr9h-x63w-vqfm"
    status: corroborated

  - id: C-R4-008
    kind: protocol-baseline
    statement: "Noise and HPKE/sealed boxes do not by themselves provide Telegraph's complete asynchronous pairing, ratchet, replay, receipt, and mailbox semantics."
    source_locators:
      - "https://noiseprotocol.org/noise.html"
      - "https://www.rfc-editor.org/rfc/rfc9180.html"
      - "https://doc.libsodium.org/public-key_cryptography/sealed_boxes"
    status: corroborated

  - id: C-R4-009
    kind: encoding
    statement: "Pairing transcript must use RFC 8949 deterministic CBOR before domain-separated hashing."
    source_locators:
      - "https://www.rfc-editor.org/rfc/rfc8949.html#name-deterministic-encoding"
    status: corroborated

  - id: C-R4-010
    kind: design-inference
    statement: "Independent safety comparison, authenticated confirmation MAC, opaque endpoints, receipt separation, atomic persistence, prekey exhaustion fail-closed, and rotation_required are Telegraph security requirements derived from the threat model."
    source_locators:
      - "docs/security/R4-telegraph-security-design.md:3-6,57-69,192-270,374-460"
    status: unverified  # design inference; not externally corroborated
```

The evidence ledger does not claim that any implementation exists or that the design has passed independent review.
