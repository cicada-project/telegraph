---
evidence_id: ADR0001-rust-first-mvp-architecture-20260823
gate: ADR0001
classification: independent-review
source_type: mixed-primary
source_locator: "docs/adr/0001-rust-first-mvp-architecture.md"
source_version_or_commit: "Telegraph planning ADR; review metadata recorded below"
accessed_at_utc: "2026-08-23T10:48:46Z"
reproduction:
  command: "read-only architecture ADR review"
  exit_code: null
  result_summary: "Rust-first architecture accepted with conditions; only T0/T1 neutral scaffold authorized"
artifact_sha256: null
status: corroborated
reviewer: independent-subagent-rust-architecture-review
reviewed_at_utc: "2026-08-23T10:48:46Z"
design_gate: accept_with_conditions
implementation_authorization: t0_t1_neutral_scaffold_only
security_claim: E2EE_not_claimed
---

# ADR 0001: Rust-first MVP architecture

- Status: Accepted for architecture planning; implementation remains gated
- Date: 2026-08-23
- Decision owner: Telegraph technical lead
- Scope: two equal Codex CLI peers, text-only MVP, and the first central relay
- Security status: design only; E2EE is not implemented or claimed

## Decision record

Product route decision (2026-08-23): the product route was approved for the
technical lead to choose a lightweight, high-performance, extensible,
Rust-first implementation. This ADR records that choice. It does not close
the open R4 conditions, select a cryptographic library, authorize a production
deployment, or provide evidence that an implementation exists.

Product-owner route approval (2026-08-23): the product owner also explicitly
approved the conditional companion route: a Rust core with the stable
`openai-codex` Python SDK bridge described by ADR 0003. This approves the
product route for planning; it does not approve direct use of the experimental
App Server CLI, close R1/R4 conditions, or claim that a bridge exists.

## Independent review disposition

The independent review by `independent-subagent-rust-architecture-review` at
`2026-08-23T10:48:46Z` is **accept with conditions**. It accepts the planning
architecture and approved route, but authorizes only T0/T1 neutral scaffold work
from the reviewed task breakdown. Relay, client, crypto/provider, bridge,
integration, and deployment implementation remain blocked pending dependency,
storage, and next-gate closure. E2EE is not implemented or verified and is not
claimed.

The implementation plan is a small Rust workspace. The first relay is referred
to only by the logical name `relay-a`; no IP address, hostname, credentials, or
deployment secret belongs in this repository.

## Context and constraints

The product contract is exactly two equal Codex CLI clients exchanging text.
Each client can own multiple local thread endpoints, but no parent/child,
Master/Subagent, group, hand-off, command, file, attachment, shared workspace,
external-chat, Web3, or generic cross-harness semantics are part of this MVP.
R1 identifies a conditional companion path using a companion-owned Codex
thread; it does not establish arbitrary existing-TUI attachment or peer input
injection. R4 recommends a Signal-style asynchronous profile conditionally,
but its exact profile, implementation library, license, persistence policy, and
independent review remain blocking decisions.

The relay is assumed malicious or fully compromised. It is a rendezvous and
store-and-forward mailbox, not a cryptographic endpoint. It may observe and
tamper with routing metadata, timing, sizes, codes, and ciphertext delivery;
the client must keep identity private keys, session state, plaintext, and any
future cryptographic operations local. Availability is not guaranteed.

## Architecture

### Workspace and dependency direction

The future workspace has these product boundaries. Names are architectural
boundaries, not a promise that crates already exist:

```text
crates/
  protocol/   versioned neutral wire framing and, after ADR 0002 review,
              approved deterministic transcript encoding and opaque envelopes
  crypto/     reviewed cryptographic-provider adapter and channel operations
  store/      isolated client-secret state and relay-opaque persistence modules
  relay/      Axum HTTP(S) service, policy, and MailboxStore orchestration
  client/     RelayTransport, pairing/channel state machine, retry, audit
  cli/        device-code UX, local configuration, and process lifecycle
```

Dependency rules:

- `protocol` has no Tokio, network, database, Codex, or crypto-provider
  dependency. It may depend on small serialization/error crates only.
- `crypto` depends on `protocol` and a separately approved provider adapter;
  it owns no HTTP or database code.
- `store` persists typed local state and relay rows but does not decrypt or
  interpret Codex text. It must expose transactions needed for crash safety.
  `store::client_secret` contains only local endpoint/channel/account/session,
  prekey-private, and rollback-anchor state; `store::relay_opaque` contains
  only mailbox, pairing, public-prekey, and transport rows. Their types and
  modules are not interchangeable. The relay crate depends only on the
  `relay_opaque` path; the client/crypto crates depend only on
  `client_secret` for private state. No relay migration may contain client
  secret-state columns.
- `relay` depends on `protocol` and `store`; it never receives plaintext or
  private key material.
- `client` depends on `protocol`, `crypto`, and local `store`, and owns the
  state machine that decides whether a decrypted message may be handed to a
  local bridge.
- `cli` depends on `client` and owns user interaction; it must not bypass the
  client state machine.
- No crate may introduce a generic intermediate representation, a global
  control plane, or an implicit shared runtime between Reflex and Telegraph.

Manifest and lock ownership is explicit. T0 owns only the workspace root
`Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`, and workspace CI.
T1 owns `crates/protocol/Cargo.toml`; T2 owns `crates/store/Cargo.toml` and
`crates/relay/Cargo.toml`; T3 owns `crates/crypto/Cargo.toml` and
`crates/client/Cargo.toml`; T4 owns `crates/cli/Cargo.toml`; T5 adds no Cargo
manifest. The root `Cargo.lock` has one integration owner (the T0 workspace
maintainer): task branches provide manifest/dependency changes but do not edit
the lock, and the integration owner regenerates, audits, and merges the lock
after each manifest merge. This avoids concurrent lock ownership and records
the exact toolchain/dependency/license closure.

T0 is also the integration owner for the small crate-root glue files
`crates/store/src/lib.rs`, `crates/client/src/lib.rs`,
`crates/cli/src/main.rs`, and `crates/store/src/migrations.rs`. T0 reserves the
module declarations and stable trait façades there; T2/T3/T4/T5 fill only the
owned subdirectories and implementations. The reserved façades are
`RelayTransport`, `CodexEndpoint`, `MailboxStore`, and `ClientSecretStore`;
their signatures are stable extension points, not generic IR. This lets each
crate task compile in isolation against a narrow stub and lets T0 perform one
explicit workspace integration after the handoffs. No later task edits these
root glue files.

### Transport and serialization

The MVP uses HTTPS with a compact, versioned CBOR protocol. The server is an
Axum service on Tokio; TLS is terminated with `rustls` (directly or through a
small Rust-facing TLS boundary that preserves the same trust contract). The
client transport is asynchronous Tokio HTTP over `rustls`.

Every request and response carries an explicit protocol major version. Until
ADR 0002 receives an independent-review disposition, T1 may implement only
neutral framing: bounded version fields, opaque byte strings, size checks,
generic lifecycle/status codes, and strict malformed-input rejection. It must
not freeze profile names, cryptographic domain tags, transcript fields,
confirmation semantics, or provider-specific key fields during that phase.
After ADR 0002 is independently reviewed, a separately reviewed protocol patch
may add its exact profile fields. Wire messages use compact integer-keyed CBOR
maps with bounded lengths and strict unknown-field/version handling. The
approved profile's pairing transcripts use RFC 8949 deterministic CBOR,
followed by its domain-separated transcript hash. JSON, WebSocket, MCP, and a
broad cross-harness wire model are not fallback transports for this MVP.

The outer envelope is intentionally boring and opaque:

```text
Envelope {
  protocol_version,
  mailbox_id,                 // opaque routing handle
  delivery_id,                // client-chosen idempotency key
  ciphertext,                 // at most 65,536 bytes
  expires_at,
  size,                       // complete outer CBOR envelope at most 69,632 bytes
}
```

Only the client-side inner payload may contain `channel_id`, `message_id`,
ratchet/sequence information, message kind, and a local thread-binding
commitment. A real Codex thread ID, workspace ID/name/path, prompt plaintext,
private key, or ratchet key is never sent to the relay.

### Narrow replacement seams

The client owns this narrow trait boundary (exact Rust signatures are a later
implementation detail):

```text
RelayTransport
  create_pairing_intent
  poll_pairing_status
  claim_pairing
  cancel_pairing
  publish_public_prekey_bundle
  reserve_public_prekey_atomically
  consume_public_prekey_atomically
  burn_public_prekey_atomically
  reconcile_prekey_reservation
  report_confirmation_complete
  reconcile_confirmation_completion
  submit_opaque_envelope
  poll_opaque_mailbox
  acknowledge_transport_delivery
```

The server owns this narrow persistence boundary:

```text
MailboxStore
  create_or_load_pairing_intent
  claim_pairing_atomically
  publish_public_prekey_atomically
  reserve_public_prekey_atomically
  consume_public_prekey_atomically
  burn_public_prekey_atomically
  reconcile_prekey_reservation
  record_confirmation_complete_atomically
  reconcile_confirmation_completion
  consume_or_expire_pairing_material
  put_opaque_envelope_idempotently
  list_pending_opaque_envelopes
  mark_transport_state
  delete_or_tombstone_expired_rows
```

The isolated local boundary is intentionally separate from both relay types:

```text
ClientSecretStore
  reserve_private_prekey_atomically
  mark_private_prekey_consumed
  burn_private_prekey
  reconcile_private_prekey_with_relay
  record_local_confirmation_complete
  persist_channel_state_before_send_or_handoff
```

`ClientSecretStore` returns `available`, `reserved`, `consumed`, `burned`, or
`uncertain`; `uncertain` is fail-closed and requires burn/quarantine. It stores
encrypted provider state and private material only in client-controlled secure
storage. No `ClientSecretStore` value is accepted by `MailboxStore`, and no
relay API accepts a private key or plaintext confirmation.

Every lifecycle operation is idempotent by its operation/reservation ID. A
public-prekey publish with the same ID and different bytes is a conflict; a
reservation has one atomic winner; consume is allowed only for the matching
reservation; burn is irreversible; reconcile returns the durable state. A
crash or uncertain private-key use burns/quarantines the prekey rather than
retrying it. Each side's `report_confirmation_complete` is recorded exactly
once; a different token for the same side is a conflict, and the relay reports
`pending`, `both_complete`, `consumed`, `expired`, or `aborted`. The relay's
confirmation state is availability bookkeeping only: clients activate from
their local identity, safety comparison, and encrypted confirmation checks.

The second valid confirmation report is a single SQLite transaction boundary.
It locks the pairing intent, verifies the first report and matching
`confirmation_complete` token, then writes the second report and atomically
transitions the intent to `BOTH_COMPLETE`/`CONSUMED` while tombstoning the
pairing material, both codes, pre-confirmation rows, and the public-prekey
reservation. The transaction either commits all of those changes or commits
none. A crash before commit leaves the prior pending state; a crash after
commit is recovered as consumed. Retrying the second report returns the same
idempotent consumed result, while a conflicting report is rejected; no retry,
expiry job, or late claim can reopen any tombstoned material.

The relay sees only public signed prekey bundles, opaque prekey IDs/hashes,
reservations, completion tokens, and ciphertext. It never generates, receives,
stores, decrypts, or reconstructs private/plaintext keys. Private prekey
reserve/consume/burn/reconcile operations belong to the isolated client-secret
store and the approved crypto adapter. These seams permit a future different
mailbox backend or transport without infecting the client state machine. A
Web3, blockchain, wallet, or generic IR adapter is not designed or implemented
by this decision.

### Relay persistence choice

The first relay uses SQLite in WAL mode. This is the smallest durable store
that provides atomic pairing claims, idempotent delivery keys, expiry
transitions, and crash recovery without operating a separate database service.
The store must use explicit transactions, a busy timeout, bounded rows, and
indexes for `(mailbox_id, status, expires_at)` and pairing-code commitments.
Tokio request handlers must not block on synchronous database work; use a
carefully bounded blocking boundary or an async SQLite driver with equivalent
transaction semantics. WAL checkpoints and expired-row deletion are explicit
maintenance operations.

SQLite is a single-relay MVP decision, not a claim that it is the long-term
cluster store. `MailboxStore` makes a later reviewed backend replacement
possible. PostgreSQL, a distributed queue, and a Web3 storage layer are
deferred until measured load or a product requirement justifies their cost.

Schema/migration ownership is split by trust boundary. T2 owns only
`crates/store/migrations/relay_opaque/**` for mailbox, pairing, public-prekey,
and transport rows. T3 owns only `crates/store/migrations/client_secret/**`
for encrypted account/session, endpoint/channel, private-prekey, dedup, and
rollback-anchor state. The T0-owned migration runner/glue invokes these as
separate namespaces/version streams; `relay` never opens the client-secret
database or migration path. Each stream has independent fresh/upgrade,
crash-recovery, backup/restore, and rollback tests, and a failed client-secret
migration fails closed without changing relay rows.

### Identity, endpoints, and channels

One OS user/Telegraph daemon has one long-term device identity. A local client
may register many random opaque thread endpoint handles. The mapping from an
endpoint handle to the real Codex thread ID and local workspace authorization
is local-only; neither value is uploaded or included in a commitment. Each
thread-to-thread pair gets its own channel ID, bootstrap/prekey state, ratchet
state, sequence/dedup state, and audit sequence. Reusing a device identity does
not merge channels.

`device_code` is a high-entropy polling capability for the initiating client;
`user_code` is a short-lived discovery input for the second client. Neither is
an identity proof or encryption proof. Activation requires identity-key and
transcript binding, independent safety-code/fingerprint confirmation, and the
reviewed confirmation-MAC flow. The exact cryptographic profile and provider
remain separate implementation-gate decisions; custom cryptographic
composition is prohibited.

### Codex companion boundary

The Rust client/daemon owns Telegraph state, receipts, retries, audit, and
supervision. Per ADR 0003, its first Codex adapter is one long-lived local
Python bridge using the stable `openai-codex` public SDK over restricted JSONL
stdin/stdout. The bridge starts/resumes only companion-owned local threads and
returns only the terminal `TurnResult.final_response`; it never directly
invokes the experimental `codex app-server` CLI, opens a socket, or attaches to
an arbitrary TUI. The stable SDK's own transitive runtime may use its internal
implementation path; Telegraph neither invokes nor exposes that path as an
App Server API. The JSONL caller cannot issue a command, tool, cwd, model, or
approval operation. A final response is handed back to the client state machine,
which encrypts and atomically persists the peer reply before RelayTransport
submission. Duplicate input IDs return cached terminal success/failure;
uncertain turn dispatch is never automatically replayed, and an explicit retry
uses a new message ID. The relay has no bridge or plaintext path.

### Reliability, abuse controls, and privacy

- Message TTL, pairing/user-code TTL, maximum envelope size, mailbox quota,
  and retry budgets are explicit policy values, not hidden defaults. The R4
  proposed starting values are seven days for ciphertext and ten minutes for
  pairing/user codes, with a five-failed-claim budget; product approval is
  required before treating them as release defaults.
- `delivery_id` makes relay submission/fetch/delete idempotent. Inner
  `message_id` and channel state make plaintext handoff idempotent. For a
  `(mailbox_id, delivery_id)` already present, an exact same protocol version,
  ciphertext bytes, size, and expiry returns the prior idempotent result; the
  same `delivery_id` with any different payload or envelope field returns
  `idempotency_conflict`, never overwrites the stored row, and never changes
  its TTL/status. A
  transport acknowledgement never means decryption, Codex acceptance, or turn
  completion; encrypted end-to-end receipts are separate state.
- Rate limits apply per client/device and origin, with route-specific limits,
  exponential backoff, jitter, bounded body parsing, and uniform errors for
  pairing claims. Error responses must not reveal whether a code exists. A
  malicious relay can still deny service.
- Expiry and cancellation are durable state transitions before payload
  deletion/tombstoning. Late retries cannot reopen an expired or consumed
  mailbox. Concurrent pairing claims have one atomic winner.
- Local audit stores opaque device/endpoint/channel/message/delivery IDs,
  state transitions, sequence/epoch status, retry/failure class, and timestamps
  or privacy-reviewed keyed digests. It must not write private keys, prekey
  private material, ratchet keys, raw codes, or plaintext by default. Relay
  logs contain no content and no raw codes; raw client IP logging is disabled
  by default and requires a separate privacy decision.

### Performance budget and observability

These are MVP targets to be measured by the integration/performance task, not
claims about an unimplemented system:

- On a two-vCPU/2-GB `relay-a` profile with SQLite WAL, 65,536-byte maximum
  ciphertext, and 69,632-byte complete deterministic-CBOR outer envelope,
  opaque enqueue and mailbox fetch service time should be p95 ≤
  100 ms and p99 ≤ 250 ms at 100 writes plus 100 reads per second, with no
  unbounded queue growth.
- A client should persist an outbound envelope before network send and finish
  local state transition in p95 ≤ 50 ms excluding network latency. Polling
  backoff must remain bounded and avoid a busy loop.
- Idle client RSS target is ≤ 64 MiB and idle relay RSS target is ≤ 256 MiB;
  all message, skipped-key, request-body, and retry buffers are bounded.
- The relay rejects ciphertext over 65,536 bytes or a complete deterministic-
  CBOR outer envelope over 69,632 bytes; clients reject malformed or over-limit
  CBOR before expensive processing.

Use `tracing` for structured events and a minimal metrics surface for request
count/latency, CBOR rejection, pairing claims/wins/failures, mailbox depth,
enqueue/fetch/ack/expiry counts, retry count, SQLite busy/transaction latency,
and process memory. Correlation uses opaque request/delivery IDs. Logs and
metrics must redact ciphertext, plaintext, codes, keys, workspace data, and
real thread IDs. Health/readiness checks report process and store status only;
no dashboard is part of the MVP.

## Rejected or deferred alternatives

- **JSON or protobuf:** larger and less constrained for this small, versioned
  envelope; CBOR provides compact bounded maps and deterministic transcript
  encoding.
- **WebSocket/MCP/remote-control transport:** not needed for store-and-forward
  and unsupported as a Telegraph peer-ingress contract by R1.
- **PostgreSQL/distributed queue:** operationally heavier than one relay and
  not justified before measured load; the store seam preserves a migration
  path.
- **Custom crypto, HPKE-only sealed boxes, Noise plus ad-hoc rekey, or
  OpenMLS:** do not meet the reviewed two-peer asynchronous profile without
  substantial new protocol work; the exact approved provider remains open.
- **Generic IR, group protocol, parent/child semantics, Web3, files,
  attachments, commands, shared workspace, dashboard, and cross-harness
  compatibility:** explicitly deferred/non-goals.

## Consequences

Positive consequences are a small deployable binary, bounded interfaces,
cheap local durability, a compact wire format, and a clear privacy boundary.
The costs are a single-relay SQLite scaling ceiling, explicit migration work
when clustering is needed, and a Rust core plus long-lived Python SDK bridge
that must stay within ADR 0003's stable companion-owned route. CBOR
compatibility, persistence behavior, cryptographic-provider selection, and
crash semantics require focused tests and independent review.

## Implementation gates and claims policy

Before shipping any message transport, the team must close R4's exact-profile,
license/support, transcript/MAC, safety-code UX, TTL/rate-limit, rollback,
rotation/repair, and automated acceptance-vector conditions, including the
independent-review disposition for ADR 0002. ADR 0003's exact stable Python
SDK/runtime tuple, fake-bridge contract, final-response return path, and
failure/idempotency tests must also be reviewed. R1's companion route must be
pinned and revalidated; arbitrary existing-TUI attachment remains unsupported.
The implementation plan in
`docs/implementation/MVP-task-breakdown.md` is a delegation map, not evidence
that any task has started or completed.

This repository must not claim that Telegraph has implemented E2EE, that the
relay cannot observe metadata or cause denial of service, that a transport ack
proves decryption, or that any independent security review has passed.
