---
adr: 0002
title: Device-code pairing and classical Olm channel profile
adr_status: accepted-with-conditions
decision: recommended-baseline-implementation-blocked
security_claim: E2EE_not_claimed
gate: R4
source_type: mixed-primary
source_locator: "docs/security/R4-telegraph-security-design.md; official vodozemac sources in §3"
source_version_or_commit: "vodozemac 0.10.0; bb39ec65357989f975e0d47f9fb35e0656180151"
accessed_at_utc: "2026-08-23T08:30:00Z"
reproduction:
  command: "read-only official-source review; git ls-remote was attempted but local TLS trust rejected GitHub"
  exit_code: null
  result_summary: "The full immutable commit was verified from the official release/tree URL and pinned source pages; no implementation was run."
artifact_sha256: null
status: corroborated
reviewer: independent-subagent-r4-security-review
reviewed_at_utc: "2026-08-23T10:49:41.9846936Z"
design_gate: accept_with_conditions
implementation_authorization: t0_t1_neutral_scaffold_only
---

# ADR 0002 — Device-code pairing and channel profile

This is a protocol decision record, not implementation authorization. The R4
design and this ADR have an independent-review disposition of **accept with
conditions**; only T0/T1 neutral scaffolding is currently authorized. The
security claim remains **E2EE not claimed**. Only two equal Codex CLI clients and
text messages are in scope. The relay is a rendezvous/mailbox and transport-ack
endpoint; it is not a cryptographic endpoint.

## Independent review disposition

The exact vodozemac Olm v1 profile was independently reviewed by
`independent-subagent-r4-security-review` at
`2026-08-23T10:49:41.9846936Z` with disposition **accept with conditions**.
Dependency/license closure, provider/storage closure, persistence and rollback
evidence, and the next implementation gate remain open. Crypto/provider,
client/channel, relay, and deployment implementation are blocked; this review
does not establish a working channel or E2EE.

## 1. Decision

Adopt the following narrow profile as the recommended implementation baseline:

* a Rust-first adapter around the fixed Apache-2.0 `vodozemac 0.10.0` release;
* one vodozemac Olm `Account` per Telegraph device and one vodozemac Olm `Session` per paired thread-to-thread channel;
* relay-generated discovery values only (`device_code` for initiator polling and a separate 50-bit Crockford `user_code` for human entry);
* an application transcript, endpoint binding, safety code, two independent user confirmations, receipts, replay policy, persistence ordering, rotation, and rollback policy defined here;
* RFC 8949 deterministic CBOR for every Telegraph object that crosses a client/relay or client/client adapter boundary.

This is explicitly **classical Olm-style 3DH plus Double Ratchet**, not Signal, X3DH, PQXDH, Sesame, or a post-quantum protocol. vodozemac does not provide Telegraph pairing, endpoint binding, relay semantics, receipts, or Codex-thread authorization; those are application protocol requirements below. No custom cryptographic ratchet, root-key extraction, or library-internal key derivation is permitted.

If the product requires Signal/PQXDH or PQ security, this ADR is the wrong baseline and is blocked pending a separately supported and licensed implementation. The minimum alternative is to defer implementation and reopen the ADR; it is not permissible to silently substitute Signal, Noise, HPKE, or a home-grown construction.

## 2. Scope and invariants

The profile has one role pair only: `A` (initiator, role `0`) and `B` (responder, role `1`). A device can own multiple opaque local endpoints, but every endpoint pair gets a fresh `intent_id`, `claim_id`, `channel_id`, transcript, prekey use, and Olm session. The real Codex thread ID, workspace ID, path, and SDK session record never cross the client boundary.

The following are hard invariants:

1. A code discovers a pending intent; it never authenticates a device.
2. No channel becomes active until both clients have locally compared the safety value through an independent authenticated path and both have sent/verified an encrypted confirmation.
3. Relay UI clicks, transport acknowledgements, physical co-location, or a shared network do not count as authentication.
4. A successful confirmation is established by decrypting the peer's confirmation with the vodozemac `Session`, not by assuming that the library exposes a root key.
5. A mutation, stale epoch, duplicate, rollback, identity change, or uncertain persistence operation fails closed.

## 3. Pinned implementation baseline and primary evidence

The recommendation is pinned to the signed official `0.10.0` tag at full commit `bb39ec65357989f975e0d47f9fb35e0656180151` (the release page displays short `bb39ec6`). The adapter must record this full commit and a dependency/license lock before implementation. Sources were checked on 2026-08-23.

| Claim | Primary locator and exact point | Result | Classification |
|---|---|---|---|
| Release identity and breaking changes | [official 0.10.0 release](https://github.com/matrix-org/vodozemac/releases/tag/0.10.0), tag commit `bb39ec65357989f975e0d47f9fb35e0656180151`, release notes | The tag is fixed; `Account::create_outbound_session`, `Account::create_inbound_session`, and `Session::encrypt` have breaking/fallible semantics called out by the release | corroborated |
| Crate identity, license, Rust floor | [raw Cargo.toml at the full commit](https://raw.githubusercontent.com/matrix-org/vodozemac/bb39ec65357989f975e0d47f9fb35e0656180151/Cargo.toml#L5-L12) | `name=vodozemac`, `version=0.10.0`, `edition=2024`, `license=Apache-2.0`, `rust-version=1.85` | corroborated |
| License text | [LICENSE at the full commit](https://github.com/matrix-org/vodozemac/blob/bb39ec65357989f975e0d47f9fb35e0656180151/LICENSE) | Apache License, Version 2.0; transitive dependency license closure is still an implementation gate | corroborated |
| Olm semantics | [versioned `olm` module docs](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/index.html) | Account has Ed25519 signing, Curve25519 identity, one-time/fallback keys; Olm sessions are asynchronous Double Ratchets and can emit pre-key messages | corroborated |
| Account/prekey API | [`Account` API](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Account.html) | `new`, identity key accessors, `sign`, `generate_one_time_keys`, `one_time_keys`, `mark_keys_as_published`, `create_outbound_session`, `create_inbound_session`, and pickling are public; inbound session creation consumes a one-time key | corroborated |
| Session API | [`Session` API](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.Session.html) | `encrypt` returns pre-key/normal Olm messages, `decrypt` returns plaintext or an error, `session_id` identifies the session, and `pickle/from_pickle` preserve session state | corroborated |
| Key and pre-key fields | [`SessionKeys`](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.SessionKeys.html) and [`PreKeyMessage`](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.PreKeyMessage.html) | The adapter can obtain the initiator base/ephemeral public key and the used one-time key as public session metadata; it never accesses a root key | corroborated |
| Olm v1 tag and feature gate | [raw pinned `session_config.rs`](https://raw.githubusercontent.com/matrix-org/vodozemac/bb39ec65357989f975e0d47f9fb35e0656180151/src/olm/session_config.rs#L33-L45) and [raw Cargo features](https://raw.githubusercontent.com/matrix-org/vodozemac/bb39ec65357989f975e0d47f9fb35e0656180151/Cargo.toml#L36-L44) | `SessionConfig::version_1()` uses AES-256/HMAC with an 8-byte truncated tag; v2 is experimental-feature-only and is forbidden here | corroborated |
| Serialization caveat | [`AccountPickle`](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/struct.AccountPickle.html) and versioned crate docs | The crate's Serde pickle format is a state container, not the Telegraph wire format; Telegraph must encrypt/atomically persist it and use deterministic CBOR only for its own objects | corroborated/inference |

`Cargo.toml` declares `default = ["libolm-compat"]`. Telegraph must use `default-features = false` unless a separate review approves the compatibility feature; no libolm pickle is a Telegraph wire format. The pinned release and its dependency graph must be built and audited on the required Linux targets before any security claim.

The adapter must explicitly construct `SessionConfig::version_1()` for both outbound and inbound session creation. Pinned Olm v1 uses AES-256/HMAC with an **8-byte truncated message tag**; this is a finite forgery/online-guessing risk, not a 256-bit integrity claim. Telegraph therefore persists an invalid-auth budget: eight authenticated-decrypt failures per channel in any ten-minute window (counter and window start are durable and included in the anchor). The eighth failure quarantines the channel and fails closed pending repair; a valid authenticated message may start a new window only before quarantine. The experimental `experimental-session-config` v2 (untruncated tag) is not enabled or used, and no claim is made that v1 has v2's tag strength.

## 4. Domain separation and byte conventions

All tags below are exact ASCII byte strings, with no NUL and no implicit separator. A hash is `SHA-256(tag || input_bytes)`. An HMAC is `HMAC-SHA-256(key, tag || input_bytes)`. Hash inputs are the exact deterministic-CBOR bytes named by the operation.

| Symbol | Exact domain tag | Use |
|---|---|---|
| `PROFILE` | `telegraph/olm-pair/v1` | Protocol profile and transcript field `0` |
| `DEVICE_CODE` | `telegraph/device-code/v1` | Device-code commitment |
| `USER_CODE` | `telegraph/user-code/v1` | User-code commitment |
| `ENDPOINT` | `telegraph/endpoint-commitment/v1` | Opaque endpoint binding |
| `PREKEY_SIG` | `telegraph/prekey-bundle/v1` | Signed prekey-bundle bytes |
| `PREKEY_HASH` | `telegraph/prekey-bundle-hash/v1` | Bundle hash in transcript |
| `TRANSCRIPT` | `telegraph/pairing-transcript/v1` | Transcript hash |
| `SAFETY` | `telegraph/safety-code/v1` | Human safety value |
| `PAIR_INIT` | `telegraph/pair-init/v1` | Signed pair-init plaintext binding |
| `CONFIRM` | `telegraph/key-confirmation/v1` | Confirmation plaintext binding |
| `INNER` | `telegraph/inner/v1` | Inner-message version binding |
| `OUTER` | `telegraph/relay-envelope/v1` | Relay envelope profile |
| `RECEIPT` | `telegraph/receipt/v1` | Receipt payload binding |
| `QR` | `telegraph/safety-qr/v1` | Independent QR payload binding |
| `ANCHOR` | `telegraph/rollback-anchor/v1` | Secure rollback-anchor MAC |

Byte strings are not base64 in CBOR. Human display uses unpadded base64url only for `device_code`, uppercase Crockford only for `user_code`, and uppercase hexadecimal only for the safety code. All integers are non-negative CBOR unsigned integers and use the shortest RFC 8949 representation.

## 5. Device identity, endpoints, and prekeys

### 5.1 Device identity

`device_id` is a fresh random 16-byte opaque local identifier. A device owns one vodozemac `Account` containing:

* a long-lived Ed25519 signing key; its 32-byte public key is `identity_ed25519`;
* a long-lived Curve25519 identity key; its 32-byte public key is `identity_curve25519`;
* a pool of one-time Curve25519 key pairs generated by `generate_one_time_keys`;
* no externally defined signed-prekey or root-key field. Olm's internal ratchet material stays inside `Account`/`Session`.

The identity private keys and all private prekeys are secure-storage-only. Ed25519 `Account::sign` signs the canonical prekey bundle and the initiator's canonical pair-init payload. A signature proves possession of the advertised key; independent safety comparison is still required for peer identity.

### 5.2 Opaque endpoint

An endpoint stores `endpoint_handle` (random 16 bytes), its local Codex thread binding, `pairing_nonce` (fresh random 16 bytes), `device_id`, and lifecycle state locally. It publishes only:

```text
endpoint_commitment = SHA-256(
  ENDPOINT || endpoint_handle || pairing_nonce
)
```

The commitment is 32 bytes. The actual thread/workspace values are neither hash inputs nor relay fields. Local authorization must check that an incoming message's committed endpoint is the intended local endpoint before any Codex handoff.

### 5.3 Signed one-time prekey bundle

The responder publishes one bundle per available OTK. Before publishing, the client creates a random 16-byte `wire_otk_id` and durably records the mapping `(wire_otk_id -> vodozemac KeyId -> public-key fingerprint)` in its own prekey inventory. The fingerprint is `SHA-256(PREKEY_HASH || otk_curve25519)`. Only a mapping in that inventory may be published or consumed; a key learned from the relay without a local mapping is rejected. The canonical CBOR map has exactly these integer keys:

| Key | Name | CBOR type and length |
|---:|---|---|
| 0 | `profile` | tstr exactly `telegraph/olm-pair/v1` (21 UTF-8 bytes) |
| 1 | `bundle_version` | uint exactly `1` |
| 2 | `device_id` | bstr exactly 16 |
| 3 | `identity_ed25519` | bstr exactly 32 |
| 4 | `identity_curve25519` | bstr exactly 32 |
| 5 | `wire_otk_id` | bstr exactly 16, random and never reused |
| 6 | `otk_curve25519` | bstr exactly 32 |
| 7 | `bundle_nonce` | bstr exactly 16, never reused |
| 8 | `expires_at` | uint Unix seconds |
| 9 | `signature` | bstr exactly 64 |

`signature` is Ed25519 over `PREKEY_SIG || deterministic_cbor(map keys 0..8 excluding key 9)`. `prekey_bundle_hash` is `SHA-256(PREKEY_HASH || deterministic_cbor(map keys 0..9))`. The initiator verifies the signature, profile, expiry, identity key continuity, wire-id/fingerprint mapping, and exact OTK public key before creating a session. Fallback keys are explicitly rejected for new Telegraph channels; exhaustion is a hard error.

### 5.4 Initiator ephemeral material

The initiator calls the pinned `Account::create_outbound_session(SessionConfig::version_1(), B.identity_curve25519, B.otk_curve25519)`. vodozemac generates the initiator's ephemeral/base key internally. The adapter obtains only the public `base_key` from the resulting pre-key message (`PreKeyMessage::base_key()`/`session_keys`) and includes that 32-byte value in the transcript. No caller-supplied ephemeral scalar, root key, or custom DH operation is allowed.

### 5.5 Olm public header metadata

The relay cannot see Olm plaintext or private keys, but the pinned Olm `PreKey`/`Message` serialization has a public header. A relay or traffic observer may parse and retain this header without decrypting: message type, sender Curve25519 identity public key, pre-key base/ephemeral public key, selected one-time public key (for a pre-key message), ratchet public key, chain/message index, and any public session/key identifiers present in the vodozemac format. These values are metadata and permit public-key correlation across envelopes. The relay must not treat them as authentication, modify them, or infer plaintext; clients must validate them against the authenticated session and transcript.

## 6. Codes, TTL, claims, and state machine

### 6.1 Code generation and display

* `device_code`: 16 CSPRNG bytes, displayed to A as 22-character unpadded base64url. It is returned only to A and is used only for polling. The relay stores `SHA-256(DEVICE_CODE || device_code)` and never needs to store the raw value at rest.
* `user_code`: uniformly sampled integer `u` in `[0, 2^50)`, encoded as exactly 10 Crockford Base32 characters using alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Leading zeroes are retained. The wire value is uppercase with no hyphen; UI may render `XXXXX-XXXXX`. Input normalizes ASCII lowercase and removes one optional hyphen, then rejects `I`, `L`, `O`, `U` and every non-alphabet character; ambiguous aliases are not accepted. Its commitment is `SHA-256(USER_CODE || uint64_be(u))`.
* Pairing intent, `pair_init`, and both confirmation inner messages have exactly 600 seconds from their respective `created_at`/`sent_at`. Relay time is authoritative for the intent; clients reject a future authenticated timestamp more than 300 seconds ahead of their clock.
* Established text, control, and receipt inner messages have a maximum/default lifetime of exactly 604800 seconds (7 days) from authenticated `sent_at`; an endpoint rejects `now > inner.expires_at`, `inner.expires_at > inner.sent_at+604800`, or `inner.sent_at > now+300`. A relay outer expiry is only a retention hint and is never trusted as endpoint expiry; its maximum is 7 days.
* A code has exactly five failed claim attempts total. Each failure increments atomically; the fifth transitions to `BURNED`. Rate limiting/backoff is per code, client/origin, and relay-wide. Invalid, expired, burned, and already-consumed values are deliberately indistinguishable on the external API.

### 6.2 Atomic lifecycle

```text
INTENT_CREATED -> CODES_ISSUED -> CLAIMED -> PREKEY_RESERVED
               -> INIT_SENT -> TRANSCRIPT_READY
               -> B_CONFIRMED -> A_CONFIRMED
               -> BOTH_CONFIRMED -> CONSUMED -> ACTIVE

Any pending state -> EXPIRED | CANCELLED | BURNED | ABORTED
ACTIVE -> ROTATION_REQUIRED | REPAIR_REQUIRED | CLOSED | REVOKED
```

The relay atomically claims `user_code` (`AVAILABLE -> CLAIMED`) and returns only an opaque `claim_id`; a concurrent loser receives no state oracle. On the winning claim, B generates `B_nonce` (fresh random 16 bytes) and the relay returns it only through the opaque claim/device-code polling path; A binds it into `pair_init` and the transcript. `device_code` polling never activates a channel. After both clients have locally confirmed the peer and exchanged encrypted confirmations, each sends a housekeeping `complete` request. The relay atomically records both reports and consumes/tombstones codes and pre-confirmation rows. This relay transition is availability bookkeeping, not authentication; clients activate only from their own local checks.

The claimant request has deterministic CBOR fields `{0: profile, 1: version=1, 2: user_code (tstr 10), 3: claimant_id (bstr16), 4: claimant_nonce (bstr16), 5: client_time (uint)}`. After a constant-time code lookup, a matching code's failed-attempt bucket is exactly `(user_code_commitment, pairing_id)` and is shared atomically by all claimants; wrong profile, reused claimant nonce, invalid client time, and other failed preconditions consume one of that same bucket's five attempts. A code that does not match any live row is charged only to `(relay_origin, claimant_id)` abuse rate limiting and cannot reveal a target row. The external response is always generic `PAIRING_UNAVAILABLE`; internal race/attempt reasons are audit-only.

Cancellation, expiry, failed confirmation, prekey failure, mismatch, or downgrade burns all pending code/claim material and quarantines late messages. A retry after `CONSUMED` returns an idempotent final result and never reopens the intent. Sequence watermarks remain durable for the whole authenticated expiry plus 7-day relay TTL; dedup/ciphertext fingerprints are tombstoned only after that period plus 300 seconds of clock skew, so a late replay still fails by ratchet/watermark even after compaction.

## 7. Pairing transcript, safety value, QR, and confirmation

### 7.1 Deterministic transcript

RFC 8949 deterministic CBOR is mandatory: definite-length maps/arrays only, shortest integer forms, no duplicate or unknown keys, and map keys sorted by their deterministic encoded-key order. This profile uses integer map keys, so transcript keys are ascending `0..24`. `transcript_cbor` is at most 4096 bytes.

| Key | Field | CBOR type and length |
|---:|---|---|
| 0 | `profile` | tstr exactly `telegraph/olm-pair/v1` |
| 1 | `profile_version` | uint exactly `1` |
| 2 | `relay_alias` | tstr exactly `relay-a` (7 bytes); never an IP/address |
| 3 | `intent_id` | bstr exactly 16 |
| 4 | `claim_id` | bstr exactly 16 |
| 5 | `device_code_commitment` | bstr exactly 32 |
| 6 | `user_code_commitment` | bstr exactly 32 |
| 7 | `A_identity_ed25519` | bstr exactly 32 |
| 8 | `A_identity_curve25519` | bstr exactly 32 |
| 9 | `B_identity_ed25519` | bstr exactly 32 |
| 10 | `B_identity_curve25519` | bstr exactly 32 |
| 11 | `A_endpoint_commitment` | bstr exactly 32 |
| 12 | `B_endpoint_commitment` | bstr exactly 32 |
| 13 | `channel_id` | bstr exactly 16 |
| 14 | `B_prekey_bundle_hash` | bstr exactly 32 |
| 15 | `B_wire_otk_id` | bstr exactly 16; maps to B's tracked vodozemac OTK |
| 16 | `B_otk_curve25519` | bstr exactly 32 |
| 17 | `A_base_key` | bstr exactly 32, extracted from the vodozemac pre-key message |
| 18 | `olm_session_id` | tstr 1..128 UTF-8 bytes, exact `Session::session_id()` |
| 19 | `initiator_role` | uint exactly `0` |
| 20 | `responder_role` | uint exactly `1` |
| 21 | `direction` | map exactly `{0: 0, 1: 1}` meaning A→B and B→A |
| 22 | `A_nonce` | bstr exactly 16 |
| 23 | `B_nonce` | bstr exactly 16 |
| 24 | `pairing_expires_at` | uint Unix seconds |

`transcript_hash = SHA-256(TRANSCRIPT || transcript_cbor)`. Both clients must independently obtain byte-for-byte identical CBOR and hash. A changed field, key order, map type, role, direction, prekey, or version is a terminal mismatch.

### 7.2 Exact `pair_init` plaintext

`pair_init` is the first encrypted A→B inner payload. Its `payload` is RFC 8949 deterministic CBOR with exactly integer keys `0..19`; it is at most 4096 bytes and has no unknown/duplicate keys:

| Key | Field | CBOR type and validation |
|---:|---|---|
| 0 | `domain` | tstr exactly `telegraph/pair-init/v1` (22 UTF-8 bytes) |
| 1 | `pair_init_version` | uint exactly `1` |
| 2 | `intent_id` | bstr exactly 16 |
| 3 | `claim_id` | bstr exactly 16 |
| 4 | `channel_id` | bstr exactly 16 |
| 5 | `A_endpoint_commitment` | bstr exactly 32 |
| 6 | `B_endpoint_commitment` | bstr exactly 32 |
| 7 | `A_nonce` | bstr exactly 16 |
| 8 | `B_nonce` | bstr exactly 16 |
| 9 | `created_at` | uint Unix seconds |
| 10 | `expires_at` | uint Unix seconds; `created_at < expires_at <= created_at+600` |
| 11 | `A_identity_ed25519` | bstr exactly 32 |
| 12 | `A_identity_curve25519` | bstr exactly 32 and equal to the vodozemac pre-key sender identity |
| 13 | `B_prekey_bundle_hash` | bstr exactly 32 |
| 14 | `B_wire_otk_id` | bstr exactly 16 and equal to the reserved local mapping |
| 15 | `device_code_commitment` | bstr exactly 32 |
| 16 | `user_code_commitment` | bstr exactly 32 |
| 17 | `sender_role` | uint exactly `0` (A) |
| 18 | `direction` | uint exactly `0` (A→B) |
| 19 | `signature` | bstr exactly 64 |

The signature input is `Ed25519.Sign(A_identity_ed25519_private, PAIR_INIT || deterministic_cbor(map keys 0..18))`. B verifies it with the key in key `11`, checks the time window, role/direction, intent/claim/channel, both endpoint commitments, both code commitments, B bundle hash, and tracked OTK mapping before accepting. The signature proves only that the pair-init fields are internally signed by whoever controls the advertised A key; it does **not** prove that this is the human's intended device. Identity authenticity still requires the independent safety-code/full-hash comparison and both encrypted confirmations.

### 7.3 Safety code and independent QR

`safety_code_bytes = SHA-256(SAFETY || transcript_hash)[0..10]`; display all 10 bytes as 20 uppercase hexadecimal characters, grouped `4-4-4-4-4` (80 bits, never truncated below 64 bits). The safety code is a comparison value, not a key.

An independently transferred QR contains deterministic CBOR with exactly:

```text
{ 0: "telegraph/safety-qr/v1", 1: 1,
  2: channel_id (bstr 16), 3: transcript_hash (bstr 32) }
```

The QR must carry the complete 256-bit transcript hash. Scanning/importing it is a local out-of-band action; a relay click or relay-supplied QR is not an independent confirmation.

### 7.4 Olm authenticated confirmation without a root-key assumption

The first A→B encrypted plaintext is `pair_init`, sent using the vodozemac session created with B's one-time key. It contains the canonical fields needed for B to verify A's signature and endpoint/channel intent, but not the transcript hash (the hash also binds A's generated base key obtained from the resulting pre-key message). B decrypts it with `create_inbound_session`, obtains the same session ID/base-key metadata, and then computes the transcript.

After B's user locally compares the safety value by face-to-face, telephone, or the independent QR, B calls the pinned `Session::encrypt` with a canonical `confirm` payload. A decrypts it using `Session::decrypt`, checks the profile, channel, session ID, transcript hash, roles, endpoint commitments, confirmation nonce, `decision=true`, and an approved method (`face_to_face`, `telephone`, or `independent_qr`). A then performs its own independent comparison and sends its own `confirm` payload. B performs the same checks. Both local states must contain `local_user_confirmed=true` and `peer_confirmation_verified=true` before `BOTH_CONFIRMED`.

The R4 requirement is **handshake/session-derived authenticated confirmation**. This ADR supersedes any earlier R4 wording that requires an extracted root key, a separately derived confirmation key, or an independent MAC key. There is no extracted or independently derived Olm root key, chain key, confirmation key, or independent MAC key. Authentication comes from the pinned Olm v1 Session's own successful authenticated decrypt in both directions, over a confirmation payload that contains the identical 32-byte `transcript_hash`; the independent 80-bit display/complete 256-bit QR comparison supplies the human identity check.

The confirmation payload is a normal encrypted Olm message, not a raw key derivation:

```text
{ 0: 2,                         # message_kind=confirm
  1: "telegraph/key-confirmation/v1",
  2: channel_id (bstr 16),
  3: transcript_hash (bstr 32),
  4: olm_session_id (tstr 1..128),
  5: sender_role (uint 0|1),
  6: receiver_role (uint 0|1),
  7: confirmation_nonce (bstr 16),
  8: decision (bool true),
  9: local_user_confirmed (bool true),
 10: confirmation_method (uint 1|2|3),
 11: sender_endpoint_commitment (bstr 32),
 12: receiver_endpoint_commitment (bstr 32) }
```

Successful bidirectional decryption and exact transcript checks establish key confirmation using only the public vodozemac `Session` encryption/decryption contract. No `root_key`, chain key, confirmation key, independent MAC key, or undocumented library state is read or invented. A replayed confirm is rejected by nonce/message-id deduplication; a confirm from a different channel/session is rejected.

## 8. Message, receipt, and relay envelopes

### 8.1 Outer relay envelope

The relay accepts deterministic CBOR with exactly integer keys:

| Key | Field | Type/limit | Relay meaning |
|---:|---|---|---|
| 0 | `profile` | tstr exactly `telegraph/olm-pair/v1` | Routing profile |
| 1 | `protocol_version` | uint `1` | Version gate |
| 2 | `mailbox_id` | bstr exactly 16 | Opaque mailbox |
| 3 | `delivery_id` | bstr exactly 16 | Idempotent transport key |
| 4 | `ciphertext` | bstr 1..65536 | vodozemac Olm message bytes; its public header is parseable metadata |
| 5 | `expires_at` | uint Unix seconds, at most 7 days after creation | Relay retention/deletion hint only; not endpoint expiry |
| 6 | `size` | uint equal to ciphertext byte length | Quota check |

The actual Olm message serialization is produced by the pinned adapter. The relay may parse the public Olm header without decrypting or modifying it. `mailbox_id`, `delivery_id`, profile/version, size, outer retention hint, timing, direction inferred from network, delivery state, and the Olm public header (message type, sender identity public key, base/ephemeral public key, selected OTK public key when present, ratchet public key, chain/message index, and public session/key identifiers) are relay-visible metadata and may be correlated. The relay cannot see `channel_id`, endpoint commitments, message IDs, receipt state, inner sent/expiry times, or plaintext; those remain inside the encrypted payload. Public-key correlation is explicitly not metadata privacy.

### 8.2 Encrypted inner payload

The plaintext passed to `Session::encrypt` is deterministic CBOR with exactly keys:

| Key | Field | Type/limit |
|---:|---|---|
| 0 | `inner_version` | uint exactly `1` |
| 1 | `channel_id` | bstr exactly 16 |
| 2 | `message_id` | bstr exactly 16 |
| 3 | `ratchet_epoch` | uint `0..2^32-1`; Telegraph channel generation only, never vodozemac's private ratchet counter |
| 4 | `sequence_domain` | uint `0=handshake`, `1=application`, `2=control`, `3=receipt` |
| 5 | `sequence` | uint `0..2^64-1`, monotonic within sender/direction/domain/epoch |
| 6 | `message_kind` | uint `1=pair_init`, `2=confirm`, `3=text`, `4=receipt`, `5=control` |
| 7 | `handshake_step` | uint `0=established`, `1=pair_init`, `2=B_confirm`, `3=A_confirm` |
| 8 | `recipient_endpoint_commitment` | bstr exactly 32 |
| 9 | `sent_at` | uint Unix seconds, authenticated and endpoint-checked |
| 10 | `expires_at` | uint Unix seconds, authenticated and endpoint-checked |
| 11 | `payload` | bstr 0..16384 for text; control-specific limit below |

`channel_id`, epoch, sequence domain, sequence, kind, handshake step, endpoint commitment, authenticated `sent_at`/`expires_at`, and message ID are checked after decryption. The outer `expires_at` is only a relay retention hint; an endpoint rejects an inner message when its authenticated expiry is in the past, its sent time is outside the approved clock-skew window, or its kind/domain/role is not allowed. A message for another endpoint is rejected before Codex handoff. `pair_init` is at most 4096 bytes, `confirm` at most 1024, a receipt at most 2048, and text payload is valid UTF-8 of at most 16384 bytes. The complete outer envelope is at most 69632 bytes.

Handshake `sequence_domain=0` and `handshake_step` are separate from established channel counters. Pair-init is only A→B `(domain=0, step=1, sequence=0)`; B confirmation is only B→A `(domain=0, step=2, sequence=0)`; A confirmation is only A→B `(domain=0, step=3, sequence=1)`. After activation, application text, control, and receipt each start their own directional sequence at `0`; no handshake sequence is reused, and no sequence maps to a private vodozemac ratchet index. Application acceptance allows at most 64 skipped messages and a maximum gap of 256; control/receipt are strict monotonic domains. Duplicate `delivery_id`, `message_id`, or `(sender_role, ratchet_epoch, sequence_domain, sequence)` is a no-op/replay rejection and never causes a second Codex input. Stale epochs, too-large gaps, invalid ratchets, bad kind/domain/role combinations, and unknown message kinds fail closed.

The complete allowed matrix is:

| `message_kind` | Activation | `sequence_domain` / `handshake_step` | Sender role and direction | Counter | `ratchet_epoch` |
|---|---|---|---|---|---|
| `pair_init` | pre-activation only | `0 / 1` | A/0, A→B only | handshake sequence `0` | Telegraph generation 0 |
| `confirm` (B) | pre-activation only | `0 / 2` | B/1, B→A only | handshake sequence `0` | Telegraph generation 0 |
| `confirm` (A) | pre-activation only | `0 / 3` | A/0, A→B only | handshake sequence `1` | Telegraph generation 0 |
| `text` | active only | `1 / 0` | either role, direction equals sender/receiver | application directional sequence | current Telegraph generation |
| `control` | active only | `2 / 0` | either role, direction equals sender/receiver | control directional sequence | current Telegraph generation |
| `receipt` | active only | `3 / 0` | receiver of referenced text → original sender only | receipt directional sequence | current Telegraph generation |

Any other kind/domain/step/role/direction/activation combination, a pre-activation established counter, or an established message carrying a handshake counter is rejected and quarantined. `pair_init` and confirmations do not consume established application/control/receipt sequence `0`. `ratchet_epoch` names only the Telegraph channel generation and never claims to expose or equal a private vodozemac ratchet index.

### 8.3 Receipts

Every receipt is a separate encrypted Olm message and outer envelope. Its payload is deterministic CBOR:

```text
{ 0: "telegraph/receipt/v1", 1: 1,
  2: channel_id (bstr 16), 3: receipt_id (bstr 16),
  4: message_id (bstr 16), 5: original_sender_role (uint 0|1),
  6: receipt_sender_role (uint 0|1), 7: receipt_receiver_role (uint 0|1),
  8: receipt_sequence (uint), 9: level (uint 1|2|3) }
```

The receiver accepts a receipt only when `channel_id` equals the current channel, `message_id` is a locally recorded message sent on this channel, `original_sender_role` matches that sent record, `receipt_sender_role` is the opposite role, `receipt_receiver_role` is the original sender, and the receipt direction/domain/sequence is valid. Unknown message IDs, wrong channels, wrong directions, and expired inner receipts are rejected, not merely ignored. Levels are monotonic and idempotent for each `message_id`: `1=decrypted`, `2=codex_accepted`, `3=turn_completed`. A duplicate or lower level is ignored; a higher level supersedes lower levels. `TransportAck` is not a receipt: it means only relay accepted/stored/fetched/deleted opaque bytes and cannot advance any E2E state.

## 9. Atomic persistence, crash points, and replay

The secure state transaction includes the independently AEAD-protected vodozemac `AccountPickle`/`SessionPickle`, epoch/sequence state, delivery/message deduplication, receipt state, prekey-use state, channel status, invalid-auth budget, and the rollback-anchor generation/hash.

### 9.1 Independent record protection for pickles

The vodozemac pickles are first serialized as raw `AccountPickle` or `SessionPickle` values through the selected Serde serializer. Telegraph must not call `AccountPickle::encrypt`, `to_libolm_pickle`, or any deterministic/library pickle encryption as its storage protection, and must not invent a ratchet or alter pickle bytes. The raw serialized bytes are then protected as one storage record with XChaCha20-Poly1305 (24-byte nonce, 16-byte tag):

```text
record_aad = deterministic_cbor({
  0: record_type,        # "account" | "session" | "channel" | "dedup" | "prekey"
  1: record_id (bstr 16),
  2: record_schema (uint),
  3: record_version (uint),
})
record_key = HKDF-SHA-256(
  K_storage_master,
  salt = record_id,
  info = "telegraph/storage-record-key/v1" || record_type || uint64_be(record_schema) || uint64_be(record_version)
)
record_ciphertext = XChaCha20-Poly1305.Seal(
  record_key, random_nonce_24, raw_serialized_pickle, record_aad
)
```

`K_storage_master` is a random 32-byte key generated once by the OS CSPRNG and stored only in the OS credential store/secure element, separate from SQLite and separate from `K_anchor`. Recovery reads the same credential-store item; if it is missing, inaccessible, or restored with a database snapshot, the client fails closed and requires device recovery/re-pair. No password-derived fallback is part of the MVP. Every record write gets a fresh random 24-byte nonce; `(record_id, record_version, nonce)` is durably unique and nonce reuse is a fatal storage error. The key source, record type/id/schema/version AAD, nonce, tag, and ciphertext are stored; plaintext pickle bytes are not.

Storage-key rotation creates a new master generation, decrypts and verifies every record, re-encrypts each with a new nonce and record version, commits the new generation, and only then erases the old credential-store key. Any interruption leaves the store in an explicit old-or-new generation or quarantines it; it never guesses. Credential-store backup/restore, secure erase, and rotation failures are audit events and fail closed.

* **Outbound:** lock the session; construct canonical inner bytes; call `Session::encrypt`; serialize the changed session pickle; record-protect it with the independent AEAD above; write that record, counters/dedup state, and the exact outer envelope with one fresh `delivery_id`; fsync and commit; only then submit to relay. A crash before the database commit has one deterministic recovery result: the old session remains authoritative, no envelope is considered sent, and the caller must retry as a new message (new `message_id`/ciphertext). A crash after commit but before send retries the same envelope and ID. A crash after send never rolls the ratchet backward.
* **Inbound:** verify outer limits/profile/retention hint; transactionally decrypt and validate the Olm message and authenticated inner expiry; serialize and record-protect the new session pickle; write that record, dedup decision, invalid-auth counter, and a local handoff job keyed by `message_id`; fsync and commit; only then hand off to the intended local endpoint. The handoff adapter must accept `message_id` as an idempotency key. A crash after handoff before the job marker is repaired by the adapter's idempotent check, never by blindly re-injecting text.
* **Receipt:** persist receipt level only after its encrypted message authenticates; transport ack cannot mutate E2E receipt state.
* **Malformed or inconsistent state:** quarantine the channel and ciphertext, emit an audit failure, and require repair/re-pair. There is no silent state reconstruction from ciphertext.

## 10. One-time prekey atomic consumption and depletion

Relay OTK rows are `AVAILABLE`, `RESERVED(intent_id)`, `CONSUMING(pairing_id,fingerprint)`, `CONSUMED`, or `BURNED`; each row is keyed by `(device_id, wire_otk_id, bundle_hash)`. At generation, the client durably records the random wire ID, vodozemac `KeyId`, public key, and public-key fingerprint before `mark_keys_as_published`; publication of an untracked key or a fallback key is rejected. An atomic relay compare-and-swap reserves exactly one available row for a claim.

The local B lifecycle is deliberately two-stage and durable:

1. **Tx1 (before library use):** in SQLite, lock the matching private OTK row; verify own tracked wire ID, `pairing_id`, bundle hash, and public-key fingerprint; reject `consuming/consumed/burned`, untracked IDs, fingerprint mismatches, and fallback messages; write `RESERVED -> CONSUMING(pairing_id, fingerprint, prekey_message_fingerprint)` and fsync/commit. Only after this commit may the process call `Account::create_inbound_session(SessionConfig::version_1(), A.identity_curve25519, pre_key_message)`.
2. **Library operation:** the pinned API removes the used OTK from the in-memory Account and returns the inbound Session; no retry is permitted if Tx1 is left behind.
3. **Tx2:** serialize and independently record-AEAD-protect the updated Account pickle (OTK removed) and new Session pickle; atomically write both records, the `CONSUMED` mapping, and pair-init dedup record; change `CONSUMING -> CONSUMED`; fsync/commit; then mark the relay reservation consumed idempotently.

Recovery scans before any pairing work. **Any** durable `CONSUMING` row, including one discovered after a crash before or during the library call, is changed in a durable transaction to `BURNED`, the pairing is failed closed/quarantined, and a fresh OTK plus new pairing is mandatory. It never attempts to reuse or infer the private key. A crash after Tx2 commit but before relay acknowledgment retries the same idempotent consumption record; a crash after relay acknowledgment is a no-op. A duplicate claim or zero available OTK returns `PREKEY_UNAVAILABLE`/`PREKEY_CONSUMPTION_UNCERTAIN`; no fallback key, reusable prekey, unauthenticated handshake, or downgrade is allowed. This is deliberately fail-closed and may sacrifice availability.

## 11. Relay retention, metadata, and error codes

Ciphertext mailbox entries have a hard default TTL of 7 days. Pairing intents, code commitments, claims, and pre-confirmation state have a hard TTL of 10 minutes. Expiry/tombstoning is durable before payload deletion and idempotent across relay crashes; late retries cannot reopen a mailbox. The relay database may contain opaque IDs, code commitments, state, ciphertext, size, TTL, attempt counters, timing, transport status, and the published signed prekey bundles/public-key fingerprints. It may also parse the Olm public headers described in §5.5. It must contain no recoverable plaintext, private key, prekey private material, session state, thread/workspace ID, or E2E receipt plaintext.

Internal protocol error codes are stable and map to the external API as documented:

| Code | Meaning | Terminal? |
|---|---|---|
| `PAIRING_UNAVAILABLE` | Invalid/expired/burned/claimed code or hidden intent state; no oracle | yes for attempt |
| `PAIRING_ATTEMPTS_EXHAUSTED` | Five failed user-code claims | yes |
| `PAIRING_CLAIM_RACE` | Atomic claim lost; no state detail | yes |
| `PAIRING_CANCELLED` / `PAIRING_EXPIRED` | Intent no longer live | yes |
| `PREKEY_UNAVAILABLE` | No available one-time prekey | yes; re-pair |
| `PREKEY_CONSUMPTION_UNCERTAIN` | Atomic private-key use not proven | yes; quarantine |
| `IDENTITY_SIGNATURE_INVALID` | Bundle or pair-init signature invalid | yes |
| `TRANSCRIPT_MISMATCH` | Canonical fields/hash differ | yes |
| `SAFETY_UNCONFIRMED` | Local independent comparison absent | yes |
| `CONFIRMATION_INVALID` | Olm decrypt or confirmation fields invalid | yes |
| `ENVELOPE_INVALID` / `PAYLOAD_TOO_LARGE` | CBOR, profile, type, or size violation | yes |
| `CIPHERTEXT_INVALID` | Olm message cannot authenticate/decrypt | yes |
| `DECRYPTION_FAILED` | Required ratchet/message key is unavailable or decryption cannot be completed; same fail-closed behavior as authentication failure | yes |
| `INVALID_AUTH_BUDGET_EXCEEDED` | Eight persisted invalid-auth attempts in ten minutes | quarantine |
| `REPLAY` / `RECEIPT_REGRESSION` | Duplicate, old, or regressive state | no-op or quarantine |
| `OUT_OF_ORDER_GAP` / `STALE_EPOCH` | Outside bounded delivery window | quarantine |
| `CHANNEL_MISMATCH` | Wrong channel/endpoint/session | yes |
| `IDENTITY_REVOKED` / `ROTATION_REQUIRED` | Old device identity or channel awaiting repair | yes |
| `ROLLBACK_DETECTED` / `STATE_INCONSISTENT` | Secure anchor or transaction mismatch | quarantine |
| `STORAGE_KEY_UNAVAILABLE` / `RECORD_NONCE_REUSE` | Independent record-AEAD key/nonce contract failed | quarantine |
| `ANCHOR_UNAVAILABLE` / `ANCHOR_OVERFLOW` | Secure anchor backend unavailable or u64 exhausted | quarantine |

The wire API uses generic `PAIRING_UNAVAILABLE` for all code oracle cases. Local audit may retain the internal code, but not raw codes or plaintext.

## 12. Rotation, revocation, quarantine, and rollback

### 12.1 Minimal secure rollback anchor

At first device creation, generate a random 32-byte `K_anchor` in OS-protected credential storage that is not part of the ordinary SQLite backup. A single writer owns the anchor lock. The canonical secure-state CBOR is a map with exactly keys `0..12`, sorted by deterministic encoded key, and includes the complete records—not only names of digests:

```text
secure_state = {
  0: schema_version (uint),
  1: device_record,
  2: account_records (array sorted by record_type then primary_key_bytes),
  3: prekey_records (array sorted by wire_otk_id),
  4: pairing_records (array sorted by intent_id),
  5: channel_records (array sorted by channel_id),
  6: counter_records (array sorted by channel_id, direction, kind),
  7: dedup_records (array sorted by channel_id, message_id),
  8: receipt_handoff_records (array sorted by channel_id, message_id, receipt_id),
  9: revocation_denylist_records (array sorted by identity_key_bytes),
 10: audit_chain_record,
 11: storage_record_index (array sorted by record_type, primary_key_bytes),
 12: anchor_generation (uint64)
}

device_record = {
  0: device_id (bstr16), 1: identity_generation (uint64),
  2: identity_ed25519_public (bstr32), 3: identity_curve25519_public (bstr32),
  4: encrypted_account_blob_digest (bstr32), 5: encrypted_account_blob_generation (uint64),
  6: storage_schema_version (uint), 7: storage_master_key_generation (uint64)
}
account_record = {
  0: account_id (bstr16), 1: account_generation (uint64),
  2: encrypted_account_blob_digest (bstr32), 3: encrypted_account_blob_generation (uint64),
  4: storage_record_schema (uint), 5: storage_record_version (uint64),
  6: prekey_inventory_digest (bstr32)
}
prekey_record = {
  0: wire_otk_id (bstr16), 1: library_key_id (uint64),
  2: public_key_fingerprint (bstr32), 3: status (uint AVAILABLE|RESERVED|CONSUMING|CONSUMED|BURNED),
  4: reservation_pairing_id (bstr16 or null), 5: reservation_fingerprint (bstr32 or null),
  6: bundle_hash (bstr32), 7: record_generation (uint64)
}
pairing_record = {
  0: intent_id (bstr16), 1: claim_id (bstr16 or null), 2: state (uint),
  3: device_code_commitment (bstr32), 4: user_code_commitment (bstr32),
  5: A_nonce (bstr16 or null), 6: B_nonce (bstr16 or null),
  7: transcript_cbor_digest (bstr32 or null), 8: local_human_confirmed (bool),
  9: peer_human_confirmed (bool), 10: confirmation_method (uint or null),
 11: attempt_count (uint), 12: expiry (uint64)
}
channel_record = {
  0: channel_id (bstr16), 1: status (uint), 2: endpoint_commitment (bstr32),
  3: peer_identity_ed25519 (bstr32), 4: peer_identity_curve25519 (bstr32),
  5: channel_generation (uint64), 6: encrypted_session_blob_digest (bstr32),
  7: encrypted_session_blob_generation (uint64), 8: transcript_hash (bstr32),
  9: invalid_auth_count (uint), 10: invalid_auth_window_start (uint64),
 11: invalid_auth_quarantine (bool), 12: quarantine_reason (uint or null)
}
counter_record = {
  0: channel_id (bstr16), 1: direction (uint 0|1), 2: kind (uint application|control|receipt),
  3: next_send (uint64), 4: highest_received (uint64), 5: replay_watermark (uint64),
  6: sparse_ranges (array of uint64 ranges)
}
dedup_record = {
  0: channel_id (bstr16), 1: message_id (bstr16), 2: delivery_id (bstr16),
  3: ciphertext_fingerprint (bstr32), 4: accepted_at (uint64), 5: tombstone_after (uint64)
}
receipt_handoff_record = {
  0: channel_id (bstr16), 1: message_id (bstr16), 2: receipt_id (bstr16),
  3: highest_receipt_level (uint), 4: receipt_sequence (uint64),
  5: handoff_state (uint), 6: handoff_idempotency_key (bstr16), 7: expiry (uint64)
}
revocation_record = { 0: identity_key_bytes (bstr32), 1: generation (uint64), 2: reason (uint), 3: deny_new_channel (bool) }
audit_chain_record = { 0: chain_schema (uint), 1: chain_head_digest (bstr32), 2: compaction_watermark (uint64), 3: last_generation (uint64) }
storage_record_index_item = { 0: record_type (tstr), 1: primary_key_bytes (bstr), 2: schema (uint), 3: version (uint64), 4: blob_digest (bstr32) }
```

Every array is sorted by the stated bytewise primary-key tuple; every nested map has a fixed key set and deterministic CBOR encoding. The canonical `secure_state` ends at key `12`; it **excludes** the independent transition journal and its status. `state_digest = SHA-256(ANCHOR || deterministic_cbor(secure_state))`, so changing a journal from `PREPARED` to `ANCHORED` cannot change `state_digest`, any secure-state record, or `audit_chain_record.chain_head_digest`. The independent sealed recovery metadata is `sealed_transition_journal = { 0: from_generation (uint64), 1: to_generation (uint64), 2: target_state_digest (bstr32), 3: status (uint PREPARED|ANCHORED) }`; it is not a member of `secure_state` and its status is not included in any state or audit digest. The OS credential-store value is `{schema_version:u64, anchor_generation:u64, state_digest:bstr32, tag:bstr32}`, where `tag = HMAC-SHA-256(K_anchor, ANCHOR || deterministic_cbor(value_without_tag))`. SQLite stores the same complete canonical state digest/generation, but never `K_anchor`. `anchor_generation` and every record generation are single-writer u64 values; overflow, a second writer, non-monotonic update, malformed CBOR, missing field, or compare-and-swap failure is fatal and quarantines the device.

The backend contract is: `read() -> exact value or unavailable`; `compare_and_swap(expected_generation, next_value) -> durable success or error`; and `erase_after_rotation() -> durable success or error`. The single-writer transition is DB-first: SQLite transaction 1 writes the complete target `secure_state` and a separate sealed journal with `status=PREPARED`, then fsyncs; the writer CASes the external anchor from `from_generation/state_digest` to the exact target `to_generation/target_state_digest`; SQLite then changes only the journal status to `ANCHORED` and fsyncs. Startup has two legal crash recoveries plus a stable completion: (a) external anchor = old and a valid `PREPARED` journal targets the next state: retry exactly one CAS, then mark `ANCHORED`; (b) external anchor = target and a valid `PREPARED` journal matches its generation/digest: mark `ANCHORED` without another CAS; (c) a valid `ANCHORED` journal matching the target is a no-op/cleanup. Any other anchor generation, digest, journal fields, or absence of a valid sealed transition is a mismatch and quarantines. Journal status changes never mutate `secure_state` or the audit-chain digest. Every successful database commit and secure-store CAS must be durable and must agree at startup. MVP requires an OS credential-store/secure-anchor independent of the SQLite snapshot; production without that backend fails closed. Simultaneous rollback of both the database and the external anchor, or a fully compromised endpoint that controls both, is endpoint compromise outside MVP protection and must not be presented as detectable.

### 12.2 Identity rotation and channel repair

On planned identity rotation, generate a new Account and device ID, mark the old identity `ROTATING`, and mark every old channel `ROTATION_REQUIRED`. Re-pair each endpoint separately with a new intent, OTK, channel ID, transcript, and safety value. After the approved transition window, atomically close old channels and delete their ratchet keys; late ciphertext/receipts are rejected or quarantined. No old-key transition certificate or silent rebinding is allowed in this profile.

On suspected compromise, mark the old identity `REVOKED`, burn pending prekeys, quarantine all old channels, and require a fresh out-of-band comparison for every repaired channel. A revocation notice may be sent over an already authenticated encrypted channel as a control message, but it is advisory to the other endpoint and cannot authenticate a replacement identity. If no old channel is available, the operator must seed a local known-peer denylist for the old identity and perform a fresh independent safety comparison; there is no silent transition certificate. The denylist blocks the revoked identity from new channels even if a relay offers it. A channel-only repair creates a new channel ID and ratchet without rotating unrelated channels. A rollback detection has the same quarantine outcome and never decrypts with restored state.

### 12.3 Bounded deduplication, receipts, and audit compaction

Each channel keeps durable contiguous watermarks plus bounded sparse ranges for each directional sequence domain. The replay window is retained through the maximum authenticated inner expiry plus the 7-day relay TTL; only then may old sparse entries be compacted. Receipt state retains the highest level and receipt sequence for each message until the same bound. Audit compaction may replace old non-secret detail with keyed digests and counters, but must retain anchor fields, revocation state, invalid-auth budget, and every replay-window watermark. Compaction that could permit an old delivery or receipt to be accepted is a storage error and fails closed.

## 13. Serialization limits and rejection rules

Every CBOR map must have the exact key set and exact integer-key order in the tables above. Reject indefinite-length items, duplicate keys, unknown keys, non-shortest integer encodings, invalid UTF-8, detached signatures, oversized fields, negative integers, trailing bytes, wrong domain tags, and mismatched declared `size`. Limits are: transcript 4096 bytes, bundle 4096, pair-init 4096, confirm 1024, receipt 2048, text 16384 UTF-8 bytes, ciphertext 65536, outer envelope 69632, pairing/confirmation TTL 600 seconds, established inner TTL 604800 seconds, future timestamp skew 300 seconds, skipped keys 64, sequence gap 256, invalid-auth budget 8 per 600 seconds, storage-record nonce 24 bytes/tag 16 bytes, and all opaque identifiers/commitments at the exact lengths stated. A vodozemac pickle is never accepted as a Telegraph envelope or as a substitute for the independent record-AEAD format.

## 14. Review blockers and prohibited claims

Before implementation, the remaining conditions must close the exact full
commit/dependency lock and licenses, disable/review `libolm-compat`, verify
Linux builds and crash/persistence tests, approve safety-code and QR UX,
approve relay/code/receipt retention, and review secure-storage/rollback-anchor
availability. R4 now records this ADR's handshake/session-derived authenticated
confirmation profile; this ADR does not claim that any implementation test
passed, that a working channel exists, or that E2EE is implemented or verified.

Do not claim Signal/PQXDH/PQ security, a Signal-equivalent protocol, E2EE implementation, relay availability, metadata privacy, arbitrary existing-TUI attachment, or protection against a compromised endpoint handling plaintext. Do not add group/Megolm, parent/child semantics, attachments, commands, Web3, or generic cross-harness IR under this ADR.
