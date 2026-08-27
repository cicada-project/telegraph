# Telegraph MVP task breakdown

This is a delegation map for future implementation work. It is not evidence
that implementation has started, that E2EE exists, or that any security review
has passed. The product route was approved on 2026-08-23 for the technical lead
to choose a lightweight, high-performance, extensible Rust-first route. The
product owner also explicitly approved the companion route on 2026-08-23:
Rust core plus the stable SDK bridge in ADR 0003. The tasks below preserve that
route and the open R4 implementation blockers.

This file is a forward-looking plan and delegation record, not implementation
authorization or evidence that any task is complete. Each task owns only the
files listed under its `File ownership`; an agent must not edit another task's
owned files. Repository execution permissions remain governed by `AGENTS.md`.
At the current phase, T0 workspace/integration work, T1 neutral framing, and
T2/T3 work in their explicitly owned files are permitted with conditions under
the subsequent implementation addendum and independent review recorded in
`docs/evidence/T2-T3-implementation-gate.md`. The addendum extends owned
implementation/test permission without rewriting ADR 0001-0004 or R4's
design-review history; R4's gate-local `t0_t1_neutral_scaffold_only` remains
historical and does not conflict with this addendum.
T4/T5/T6+ remain blocked, including CLI, bridge, integration, release, and
deployment work. The T0 integration owner may change root workspace membership,
`Cargo.lock`, and reserved crate-root glue only at an accepted handoff; T2/T3
must not cross ownership boundaries. ADR and governance documents have been
updated through the review workflow, but that does not relax AGENTS.md, file
ownership, implementation scope, security gates, or the claims policy.

### Current T2/T3 implementation-gate disposition

- Reviewer: `telegraph-t2-t3-implementation-gate-reviewer-01`
- Reviewed at (UTC): `2026-08-23T13:00:24Z`
- Source commit: `ca37d28bed9a50b776b2f8f2d3396df771207186`
- Disposition: T2 relay/store/API and T3 crypto/client-state are **authorize
  with conditions**; T4/T5/T6+ remain blocked.
- The 30 R4 acceptance vectors have not been executed. No implementation result
  may claim E2EE or production readiness; every result requires independent
  review.

## Shared rules for every implementation task

- Keep the MVP to exactly two equal Codex CLI peers and text messages.
- Treat “exactly two” as a per-channel invariant: one device may serve independent endpoints across multiple local workspaces and multiple peers, but no channel becomes a group or shared-workspace protocol. Client and central relay may be physically separate; preserve the [topology addendum](../evidence/product-topology-and-scope-addendum.md).
- Keep real Codex thread IDs, workspace IDs, names, and paths local to the
  client. The relay sees only opaque endpoint/mailbox handles and ciphertext.
- Do not add a generic IR, dashboard, group chat, files, attachments, shared
  workspace, command execution, parent/child semantics, automatic hand-off,
  external chat, Web3, blockchain, wallet, or other-harness compatibility.
- Do not invent cryptography. The crypto task may proceed only after the exact
  reviewed profile/provider/license/support decision is recorded; otherwise it
  must stop with a blocker report.
- Do not log plaintext, private keys, raw pairing codes, real thread IDs, or
  unredacted workspace data. Do not put server addresses, credentials, tokens,
  private keys, cookies, or `.env` files in Git.
- `relay-a` is the logical name of the first deployment. Never write its IP or
  a production hostname into source, tests, docs, fixtures, or logs.
- `device_code`/`user_code` are short-lived per-intent rendezvous inputs, not identity or long-term per-thread key-directory services; public prekeys are bounded bootstrap metadata with expiry and consume/burn lifecycle.
- The approved Codex route is ADR 0003's Rust core plus stable
  `openai-codex` Python JSONL bridge. Never replace it with direct experimental
  App Server CLI/JSON-RPC, WebSocket, MCP, Remote Control, or private internals.
- Use focused Rust crates and narrow traits from ADR 0001. A passing build is
  not a security claim; all tasks must state what they did and did not prove.

## T0 — Rust workspace scaffold

### User flow

A maintainer clones the repository, selects the pinned Rust toolchain, and can
inspect a valid root workspace/ownership manifest. Once T1–T4 hand off their
crate manifests, the T0 integration owner runs the full format, check, lint,
and test workflow for `protocol`, `crypto`, `store`, `relay`, `client`, and
`cli`.

### Scope

- Create the Cargo workspace and the six boundary crates named in ADR 0001.
  T0 must not own implementation subdirectories; it owns only the explicitly
  listed crate-root glue/module declarations and workspace/toolchain/lock
  integration. Each crate manifest is owned by its later crate task.
- Pin the reviewed toolchain policy and conservative release profiles.
- Establish dependency direction, common error/result conventions, feature
  flags, lint policy, and CI jobs for `fmt`, `check`, `test`, and `clippy`.
- Reserve the crate-root integration glue: module declarations in
  `store/src/lib.rs`, `client/src/lib.rs`, and `cli/src/main.rs`, the stable
  trait façade (`RelayTransport`, `CodexEndpoint`, `MailboxStore`,
  `ClientSecretStore`), and `store/src/migrations.rs`. These files contain no
  product behavior; later tasks fill only their owned subdirectories.

### Non-goals

- No relay, transport, database schema, cryptography, Codex bridge, CLI flow,
  generic IR, or deployment configuration.
- No unreviewed dependency chosen merely to make a skeleton compile.

### Acceptance conditions

- The root workspace manifest parses and names the six intended members; after
  T1–T4 manifest handoff, a clean integrated checkout passes `cargo fmt
  --check`, `cargo check --workspace`, `cargo test --workspace`, and the agreed
  clippy command on the pinned toolchain. Before that handoff, T0 records the
  full check as pending rather than creating placeholder crate manifests.
- Cargo metadata shows the intended dependency DAG and no cycle between
  `protocol`, `crypto`, `store`, `relay`, `client`, and `cli`.
- The root `Cargo.lock` is generated and merged only by the T0 integration
  owner. T1–T5 submit manifest/dependency changes without editing the lock;
  T0 regenerates it after each accepted manifest merge and records the
  toolchain/license audit.
- The reserved module declarations and trait façade compile against isolated
  stubs, and the T0 integration owner has one explicit post-handoff workflow
  that checks all six crates together. T2/T3/T4/T5 do not edit these glue
  files.
- CI uses no credentials and does not embed a relay address.
- The task reports all dependency licenses and any unresolved R4 gate; it does
  not claim an implementation or E2EE.

### Risks

- Premature shared utility crates can become an accidental generic runtime or
  IR; keep the scaffold deliberately small.
- A toolchain/dependency pin may conflict with the eventual crypto provider;
  record the conflict instead of weakening the pin silently.

### Dependencies

ADR 0001 and the product boundary are required. No other implementation task
is required; this task must not pretend R4 is closed.

### File ownership

Root `Cargo.toml`, root `Cargo.lock` (single integration/merge owner),
`rust-toolchain.toml`, `.cargo/`, CI files under `.github/workflows/`, and the
integration glue `crates/store/src/lib.rs`, `crates/client/src/lib.rs`,
`crates/cli/src/main.rs`, and `crates/store/src/migrations.rs`, which contain the
reserved trait façades and module declarations. T0 owns no crate manifests or
owned implementation subdirectories; T1–T5 fill only the paths listed below.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the workspace maintainer. In the Telegraph repository, implement
> only T0 from `docs/implementation/MVP-task-breakdown.md`. Build a minimal
> Rust workspace with crates `protocol`, `crypto`, `store`, `relay`, `client`,
> and `cli`, enforce the ADR dependency direction, and add CI for format,
> check, test, and clippy. Do not edit any crate manifest or implementation
> subdirectory owned by T1–T5. Reserve only the explicitly listed crate-root
> module declarations and stable trait façade described in ADR 0001;
> do not implement networking,
> SQLite, CBOR models,
> cryptography, pairing, Codex integration, generic IR, dashboards, files,
> commands, groups, or Web3. Do not add credentials or a relay IP/hostname.
> Touch only T0-owned files. Run root/isolated checks now, and run the full
> workspace check only after T1–T4 manifest/glue handoffs are merged. Report
> exact versions, dependency/license concerns, and explicitly say that E2EE is
> not implemented.

## T1 — Protocol model and compact CBOR framing

### User flow

When a client submits or polls a message, both sides decode the same compact,
versioned CBOR envelope, reject malformed/oversized input before expensive
work, and preserve opaque ciphertext without interpreting it.

### Scope

- Before ADR 0002 receives an independent-review disposition, define only
  neutral integer-keyed, versioned CBOR framing: bounded opaque bytes, version,
  generic lifecycle/status codes, and bounded error responses. Do not freeze a
  profile name, crypto domain tag, transcript field, confirmation field, or
  provider-specific key type in this phase.
- After ADR 0002's independent review approves the profile, a separately
  reviewed T1 patch may add exact pairing discovery, public-prekey metadata,
  opaque-envelope, and transport-ack fields.
- Define opaque IDs, protocol major/minor handling, message size limits, and
  validation rules with stable error classes.
- If and only if ADR 0002 is independently approved, provide its RFC 8949
  deterministic transcript encoding, including `relay-a` as a logical alias
  and no real thread/workspace ID. Expose canonical bytes to the crypto
  adapter; do not perform cryptographic key operations here.
- Add round-trip, canonical-byte, unknown-version, truncation, duplicate-key,
  and resource-limit tests.

### Non-goals

- No key generation, encryption/decryption, ratchet, HTTP, SQLite, relay
  policy, Codex input, generic IR, or plaintext message storage.
- No claim that deterministic encoding alone provides authentication or E2EE.

### Acceptance conditions

- Neutral framing fixtures round-trip and reject malformed/oversized input.
  Profile-specific canonical transcript fixtures are allowed only after ADR
  0002's independent-review disposition is recorded and must then produce
  identical canonical bytes on repeated runs.
- Unsupported major versions and malformed/non-canonical security-sensitive
  inputs fail closed with bounded errors.
- Envelope decoding enforces exactly 65,536 bytes maximum ciphertext and
  69,632 bytes maximum complete deterministic-CBOR outer envelope; it never
  allocates from untrusted lengths without a bound.
- Relay-facing types contain no fields for real Codex thread/workspace IDs,
  plaintext, private keys, or ratchet keys.
- Before manifest handoff, only crate-local or isolated temporary-workspace
  checks are run; no T1 task claims a full workspace check. T0 runs the full
  workspace check after all manifest and glue handoffs. The report separates
  encoding evidence from future security claims.

### Risks

- CBOR library defaults may permit indefinite lengths, duplicate keys, or
  non-deterministic maps; configure and test strict behavior explicitly.
- A convenient public model can leak sensitive fields into relay code; keep
  opaque and local-only types distinct at compile-time where practical.

### Dependencies

T0 and an independent-review disposition for ADR 0002. Until that disposition
is approved, T1 is neutral-framing-only and must record the profile blocker;
it may not add provider-specific fields or a crypto dependency.

### File ownership

`crates/protocol/Cargo.toml`, `crates/protocol/src/**`, protocol fixtures under
`crates/protocol/tests/**`, and protocol-specific documentation/tests only.
Before handing off its manifest, T1 uses only a crate-local/isolated temporary
workspace; T0 owns the post-handoff workspace check and root lock.
T1 never edits the root `Cargo.lock`; it sends dependency changes to the T0
integration owner.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the protocol engineer. Implement only T1 in the Telegraph
> repository. Define strict compact integer-keyed versioned CBOR models for
> bounded neutral opaque relay framing and errors. Until ADR 0002 has an
> independent-review disposition approving the profile, do not add profile
> names, crypto domain tags, transcript fields, confirmation semantics, or
> provider-specific key types. Only after that disposition may you add its
> exact RFC 8949 transcript fields; do not hash, encrypt, or generate keys in
> this crate. Ensure relay types cannot carry real Codex
> thread/workspace IDs, plaintext, private keys, or ratchet keys. Add tests for
> neutral canonical framing bytes, malformed/duplicate/truncated CBOR, version
> rejection, and
> 65,536-byte ciphertext and 69,632-byte complete outer-envelope bounds.
> Touch only T1-owned files; do not add HTTP, SQLite, crypto, generic IR,
> dashboard, group, file, command, Web3, or other-harness code. Before manifest
> handoff run only crate-local/isolated temporary-workspace checks; do not run
> or claim a full workspace check. Hand the manifest and results to T0 for
> integration, report what remains blocked by ADR 0002, and do not claim E2EE.

## T2 — Relay mailbox store and HTTP(S) API

### Implementation-gate status

T2 is authorized with conditions by the current independent gate. It may touch
only the T2-owned paths below and must keep the relay opaque: no plaintext,
private key, decryption, key generation, session opening, Codex interpretation,
CLI/bridge/deployment work, or root lock/glue edits. Proposed TTLs remain
configurable design values pending product approval, not release defaults.
T2's tests and handoff require independent review; the R4 vectors are future
acceptance requirements and have not been executed by this gate.

### User flow

Client A creates a pairing intent and polls it; client B claims the displayed
short user code; either client submits an opaque ciphertext envelope; the peer
publishes/reserves a public prekey, both clients report locally verified
`confirmation_complete`, and the peer polls and acknowledges transport
delivery. Expiry, duplicate retries, prekey uncertainty, and concurrent claims
have deterministic outcomes without revealing code state.

### Scope

- Implement `MailboxStore` against SQLite with WAL, explicit transactions,
  busy-timeout/backoff, indexes, bounded rows, crash-safe expiry, and
  idempotency by `delivery_id`.
- Implement the opaque public-prekey lifecycle and pairing completion lifecycle:
  publish, reserve, consume, burn, reconcile, and one report per side for
  `confirmation_complete`. Reservations have one atomic winner; uncertain or
  crashed use burns/quarantines the reservation; completion reports are
  idempotent, conflicting reports fail, and the relay never activates a client
  channel by itself.
- On the second valid confirmation report, commit the second report,
  `BOTH_COMPLETE`/`CONSUMED` transition, pairing material/code tombstones,
  pre-confirmation tombstones, and public-prekey reservation tombstone in one
  SQLite transaction. A crash before commit remains pending; a crash after
  commit recovers consumed; retries are idempotent and never reopen material.
- Implement the Axum/Tokio HTTP(S) API and `rustls` boundary for pairing,
  prekey metadata, mailbox submit/poll/ack, health, and readiness.
- Enforce protocol/version/body-size validation from T1; never deserialize
  opaque ciphertext into plaintext.
- Enforce exactly 65,536 bytes maximum ciphertext and 69,632 bytes maximum
  complete deterministic-CBOR outer envelope, including framing overhead.
- Enforce route/client/origin rate limits, mailbox quotas, TTL policy, uniform
  claim errors, five-attempt proposed code budget, and durable consumed/
  expired/cancelled tombstones. Treat R4 proposed 7-day message and 10-minute
  pairing/user-code TTLs as configurable pending product approval.
- Add redacted `tracing` events and metrics for latency, claims, mailbox depth,
  expiry, retries, SQLite contention, and malformed requests.

### Non-goals

- No decryption, key generation, session opening, Codex interpretation,
  plaintext endpoint, generic IR, Web3 backend, cluster scheduler, dashboard,
  or production hostname/IP.
- No claim that HTTPS or transport acknowledgement is end-to-end encryption
  or proof of peer authenticity.

### Acceptance conditions

- Unit and API tests prove atomic concurrent claim (one winner), cancellation,
  expiry, no code reuse, idempotent submit/ack/delete, uniform invalid-code
  errors, and bounded body/resource use.
- The same `(mailbox_id, delivery_id)` with identical protocol version,
  ciphertext bytes, size, and expiry returns the prior result. The same
  `delivery_id` with a different payload or envelope field returns
  `idempotency_conflict`, never overwrites the row, and never changes TTL or
  status. Prekey publish/reserve/consume/burn/reconcile and both confirmation
  completion reports have equivalent atomic/idempotent/conflict tests.
- A crash at every SQLite confirmation-complete step proves that the second
  report and all required tombstones commit together or not at all; no retry,
  expiry worker, or late claim reopens codes, pre-confirmation rows, or the
  public-prekey reservation.
- SQLite restart/crash tests preserve durable state transitions and never
  reopen consumed or expired pairing material.
- Relay database rows and logs contain only opaque routing IDs, protocol
  metadata, ciphertext bytes, sizes, TTL/status, and public discovery material;
  no plaintext, private keys, raw codes, real thread/workspace IDs, or secrets.
- A measured two-vCPU/2-GB test profile records the ADR target at 100 writes +
  100 reads/s (p95 service time ≤100 ms, p99 ≤250 ms) or reports an actionable
  deviation; no unbounded queue is permitted.
- `cargo test` and a bounded API/load test pass without starting a production
  relay. The report calls the first logical deployment `relay-a` only.

### Risks

- SQLite writer contention, checkpoint stalls, or blocking Tokio handlers can
  violate latency and crash semantics; measure and bound them.
- Rate-limit and code-error behavior can become an enumeration oracle; test
  timing/response uniformity and avoid detailed state messages.
- Axum/rustls defaults may accept bodies or versions beyond the policy; reject
  before storage.

### Dependencies

T0 and T1 neutral framing. T3 consumes this API; profile-specific public
prekey fields require ADR 0002's independent-review disposition. T2 must be
testable with opaque fixtures and must not wait for a private-key or crypto
implementation.

### File ownership

`crates/store/Cargo.toml`,
`crates/store/src/relay_opaque/**`,
`crates/store/migrations/relay_opaque/**`, `crates/relay/Cargo.toml`,
`crates/relay/src/**`,
relay API tests under `crates/relay/tests/**`, and non-secret store/API
fixtures. Deployment files belong to T7. T0 owns `crates/store/src/lib.rs`
and `crates/store/src/migrations.rs`; T2 owns no `store::client_secret` module and
never edits the root `Cargo.lock`.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the relay engineer. Implement only T2. Build the Tokio/Axum HTTPS
> relay boundary with rustls and a SQLite WAL `MailboxStore` that stores only
> opaque mailbox/delivery IDs, protocol metadata, ciphertext bytes, sizes,
> TTL/status, and public discovery data. Implement atomic pairing claims,
> cancellation/expiry tombstones, idempotent delivery IDs, strict CBOR/body
> limits, route/client/origin rate limits, quotas, uniform code errors, and
> redacted tracing/metrics. Implement opaque public-prekey publish/reserve/
> consume/burn/reconcile and both-side confirmation-complete bookkeeping with
> atomic conflict/failure semantics. Identical delivery IDs are idempotent;
> a different payload for the same ID returns `idempotency_conflict` and never
> overwrites. Validate the ADR performance target under a bounded local load
> test. Enforce 65,536-byte ciphertext and 69,632-byte complete outer-CBOR
> limits. The second valid confirmation report must atomically commit both-side
> completion plus code/pairing/pre-confirmation/public-prekey tombstones in one
> SQLite transaction; crash/retry must never reopen them. Relay may store only
> public signed prekey bundles and opaque IDs/hashes;
> it must never generate, receive, persist, or reconstruct private/plaintext
> keys. Do not decrypt, generate keys, open sessions,
> interpret Codex text, add generic IR, dashboard, group, files, commands,
> Web3, cluster code, or any relay address/IP. Touch only T2-owned files.
> Run tests and report all deviations. Transport acks are not E2E evidence;
> explicitly state that E2EE is not implemented.

## T3 — Crypto adapter and client state

### Implementation-gate status

T3 is authorized with conditions by the current independent gate. It may touch
only the T3-owned paths below; it must not edit T0 glue, the root lock, T2 relay
paths, CLI, bridge, or deployment files. Provider/dependency/license/support
closure, secure client-secret storage and migration evidence, and the R4
profile conditions remain mandatory. T3 results require independent review and
must not claim E2EE or production readiness; the R4 vectors remain unexecuted.

### User flow

A client creates one device identity, registers several opaque local thread
endpoints, completes a reviewed pairing for one endpoint pair, persists channel
state, encrypts a text message before transport, decrypts an accepted message
once, and emits distinct transport versus end-to-end receipt state.

### Scope

- Define `CryptoProvider`/channel adapter seams so the client does not depend
  on provider-specific types. Use only the exact protocol/profile/library,
  license, immutable commit, and support posture approved after R4; stop if
  that decision is not recorded.
- Define the client-side `RelayTransport` trait and its HTTPS implementation
  against T2's API. It may move opaque CBOR envelopes and transport
  acknowledgements, but it must not expose plaintext, key/session operations,
  or real thread/workspace identifiers.
- Implement device-level identity lifecycle, signed/fallback/one-time prekey
  inventory as approved by the profile, opaque endpoint handles and pairing
  commitments, and one independent channel/ratchet/dedup state per
  thread-to-thread pair.
- Implement the isolated `store::client_secret` lifecycle for private prekeys:
  atomic reserve, consume after proven inbound-session use, irreversible burn
  on uncertainty, and reconcile with the relay's opaque reservation. Record
  each side's locally verified `confirmation_complete` and reconcile it with
  the relay without treating relay bookkeeping as authentication.
- Implement the independent client-secret migration stream under
  `crates/store/migrations/client_secret/**`: fresh install, upgrade, crash
  recovery, backup/restore, rollback-anchor validation, and fail-closed
  migration failure. It must never share relay-opaque migration versions or
  open relay tables.
- Implement canonical transcript binding, safety-code/fingerprint material,
  confirmation MAC flow, bounded skipped-key/replay handling, stale epoch and
  endpoint mismatch rejection, and fail-closed prekey exhaustion.
- Persist outbound state+ciphertext before send and inbound ratchet/dedup state
  before local handoff; expose crash-recovery/rollback/rotation-required
  outcomes without silently repairing old channels.
- Keep all real Codex IDs/workspace authorization in a local store and produce
  privacy-reviewed audit records without keys, codes, or plaintext.

### Non-goals

- No custom cryptographic composition, library substitution without review,
  relay implementation, HTTP server, CLI UX, Codex bridge, group/MLS mode,
  Web3, generic IR, file/command/attachment handling, or E2EE marketing claim.

### Acceptance conditions

- R4 positive/negative vectors pass for transcript mismatch, identity/key
  substitution, confirmation failure, replay/duplicate, stale epoch, bounded
  out-of-order delivery, endpoint cross-injection, rollback, rotation/revoked
  device, atomic prekey consumption, and receipt monotonicity.
- Two endpoints on one device use the same device identity but distinct
  channel IDs and state; channel A cannot decrypt or inject into channel B.
- Outbound and inbound crash tests demonstrate the required persistence order;
  a failed state recovery fails closed and requests controlled repair.
- Audit inspection confirms no private key, prekey private value, ratchet key,
  raw code, real thread/workspace ID, or default plaintext retention.
- A duplicate operation with the same ID and identical payload is a no-op or
  prior result; a changed payload is `idempotency_conflict` and cannot overwrite
  client-secret state, channel state, or a persisted envelope. Relay and client
  prekey states reconcile as `available`, `reserved`, `consumed`, `burned`, or
  `uncertain`; uncertainty fails closed and burns/quarantines the prekey.
- Client-secret migration tests prove that a failed or rolled-back secret-state
  migration cannot alter relay-opaque rows, and that T0's migration runner
  invokes the client-secret stream separately from T2's relay stream.
- The task includes dependency/license/support evidence and says “E2EE not
  claimed pending independent review” until T8 passes.

### Risks

- ADR 0002 is the selected classical Olm-style baseline only after its
  independent-review disposition. Selecting or coding a provider before that
  disposition would create a false security boundary.
- Persistence rollback and crash ordering can invalidate otherwise sound
  protocol code; treat storage as part of the security boundary.
- Provider API churn or incompatible license terms can block the task; keep
  the adapter narrow and report the blocker.

### Dependencies

T0 and T1 neutral framing; T2's relay API contract must be available for
integration, and ADR 0002 must have an independent-review disposition before
profile-specific fields or provider code. T3 may use a deterministic
in-memory transport fixture. The approved profile/provider and legal/support
decision are mandatory before production cryptographic code.

### File ownership

`crates/crypto/Cargo.toml`, `crates/crypto/src/**`, crypto test vectors under
`crates/crypto/tests/**`, `crates/client/Cargo.toml`,
`crates/client/src/state/**`, `crates/client/src/channel/**`,
`crates/client/src/transport/**`, `crates/store/src/client_secret/**`, and
`crates/store/migrations/client_secret/**`. T0 owns
`crates/client/src/lib.rs` and `crates/store/src/migrations.rs`; T3 owns no
`store::relay_opaque` files, relay files, CLI files, T0 glue, or root
`Cargo.lock`.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the client-state, transport, and cryptography adapter engineer.
> Implement only T3, and first verify that R4's exact protocol profile,
> immutable commit, license, and external-support decision is approved by the
> independent review of ADR 0002. If it is not, stop after writing a blocker
> report in the task output and do not
> invent crypto. When approved, hide the provider behind a narrow
> `CryptoProvider` plus the T0-declared client-side `RelayTransport` and HTTPS
> adapter,
> implement one device identity with many opaque local
> endpoints and an independent channel/ratchet/dedup state per endpoint pair,
> plus isolated private-prekey reserve/consume/burn/reconcile and both-side
> confirmation-complete state. Make relay reservations/public bundles opaque;
> never send private or plaintext keys to the relay. Same ID/same payload is
> idempotent; same ID/different payload is `idempotency_conflict` and cannot
> overwrite state. Keep the store modules and types separated as ADR 0001
> requires. Implement the independent client-secret migration stream under
> `crates/store/migrations/client_secret/**` with fresh/upgrade/crash/backup/
> rollback tests, separate from relay-opaque migrations; a failed migration
> fails closed and cannot alter relay rows. Also implement deterministic
> transcript/safety confirmation,
> bounded replay/order handling, atomic prekey consumption, crash-safe
> state-before-send and state-before-handoff, rotation/revocation/repair, and
> privacy-safe audit. Touch only
> T3-owned files. Do not add relay HTTP, CLI UX, Codex bridge, generic IR,
> dashboard, groups, files, commands, Web3, or unsupported provider code. Run
> the R4 vectors and dependency checks. Never claim E2EE before T8 review.

## T4 — Device-code pairing CLI

### User flow

User A runs the CLI to create a pairing intent and sees a short `user_code`
for the other client; A polls using a non-manual high-entropy `device_code`.
User B enters the short code, both clients display the safety code/fingerprint,
users compare it through an authenticated channel or approved independent QR,
and both confirm. Cancellation, expiry, mismatch, and retry have clear bounded
outcomes.

### Scope

- Implement only pairing/device-code CLI commands for local endpoint selection,
  intent creation,
  polling, user-code claim, safety-code/fingerprint confirmation, cancellation,
  status, and local audit inspection.
- Keep `device_code` in protected local process/state handling; never ask the
  human to type it. Treat `user_code` as discovery only, not identity proof.
- Surface uniform errors, backoff, attempt exhaustion, consumed/expired/burned
  states, rotation-required/re-pair states, and no-secret logging.
- Use `RelayTransport` and T3 state APIs; never bypass channel activation or
  inject directly into a Codex thread.

### Non-goals

- No new protocol, key generation, relay server, generic IR, dashboard, group
  chat, files, commands, Web3, or arbitrary existing-TUI attachment.
- No claim that a code, CLI display, or relay UI alone authenticates a peer.

### Acceptance conditions

- A scripted two-client flow covers create, poll, claim, independent safety
  comparison, dual confirmation, activation, cancel, expiry, wrong code,
  attempt exhaustion, and retry idempotency.
- The CLI never prints raw private keys, plaintext peer content, real thread or
  workspace IDs, or the high-entropy device code in the user audit by default.
- It cannot activate a channel before both local confirmation-MAC checks and
  approved confirmation state; a relay-only “confirm” is rejected.
- Human-facing code formatting and complete transcript-hash QR/manual flow are
  documented as product-approved behavior or an explicit blocker.
- The task works with a logical `relay-a` configuration and no embedded address.

### Risks

- A convenient UX can accidentally turn rendezvous codes into authentication;
  keep wording and state transitions precise.
- Terminal history, crash dumps, or verbose errors can leak codes or IDs;
  test redaction and protected handling.

### Dependencies

T2's transport API and T3's approved pairing/channel state. T5 is not required;
pairing must be testable without a live Codex bridge.

### File ownership

`crates/cli/Cargo.toml`, `crates/cli/src/pairing/**`, pairing CLI integration tests under
`crates/cli/tests/pairing/**`, and pairing-only help/UX fixtures.
T0 owns `crates/cli/src/main.rs` and its module declarations; T4 owns no
`crates/cli/src/codex_bridge/**`, bridge tests, T0 glue, other crate manifests,
or root `Cargo.lock`. T4's crate-local check uses the T0 main stub; T0 runs
the full CLI workspace integration after T4/T5 handoff.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the pairing UX engineer. Implement only T4. Build the device-code
> and user-code CLI flow on top of `RelayTransport` and the reviewed T3 state
> machine: endpoint selection, intent/poll, human claim, independent safety
> comparison or approved full-hash QR, dual confirmation, cancellation,
> expiry, bounded retries, and redacted local audit. Never ask the user to type
> `device_code`; never call a code an identity proof; never activate from relay
> UI confirmation alone. Touch only T4-owned pairing files; do not edit the
> T0-owned CLI main/module declarations, bridge modules, or root lock. Do not
> add crypto,
> relay, Codex bridge, generic IR, dashboard, groups, files, commands, Web3,
> or a production IP/hostname. Test the scripted positive and negative flows,
> report unresolved product UX decisions, and state that E2EE remains
> unclaimed pending independent review.

## T5 — Stable Python SDK JSONL Codex bridge

### User flow

A user launches Telegraph with a locked, long-lived local Python bridge.
Telegraph owns a companion Codex thread through the stable `openai-codex`
Python SDK, receives an authenticated peer text through the T3 client state
machine, submits it over a restricted local JSONL pipe, waits for the SDK's
terminal `TurnResult.final_response`, and sends that response back through T3's
encrypted channel. An arbitrary already-running TUI is not attached.

### Scope

- Implement a narrow Rust `CodexEndpoint`/`CodexBridge` supervisor and a
  restricted versioned JSON Lines v1 protocol over inherited stdin/stdout.
  Start one warm Python process per OS user/daemon; never spawn a Python or
  Codex process per peer message.
- Implement the Python side with only the stable public `openai-codex` API:
  `AsyncCodex`, companion-owned `thread_start`/`thread_resume`, one ordered
  queue per endpoint, `AsyncThread.turn`, and terminal
  `TurnResult.final_response`. Pin an exact tested Python/SDK/runtime tuple and
  lock hashes; do not call the experimental `codex app-server` CLI directly.
- Pass only bounded local opaque endpoint/message IDs and plain text over JSONL.
  Keep the real Codex thread ID in the bridge-local endpoint store. Do not send
  it to Rust audit, relay code, or the JSONL response.
- The JSONL caller cannot select or issue a command, tool, cwd, model, approval,
  or other caller-controlled execution operation. The stable SDK may use its
  own transitive runtime internally; T5 does not invoke or expose that runtime
  as a Telegraph App Server API.
- On a successful final response, hand the plain response only to T3. T3
  creates the peer reply message, encrypts it, persists channel state plus the
  exact ciphertext before relay submission, and retries the same
  `delivery_id`. No response text crosses the relay in plaintext.
- Define deterministic failure/idempotency semantics: duplicate
  `(endpoint,message_id)` with the same text returns the cached terminal result
  and never runs a second turn; a different text returns
  `idempotency_conflict`; `backpressure`, known timeout/cancel, and
  `turn_outcome_unknown` are distinct. A crash after dispatch never
  automatically replays the uncertain turn or fabricates a final response;
  duplicate failure requests return the same terminal status, and a deliberate
  retry requires a new message ID. Any failure receipt sent to the peer goes
  through T3 encryption and is itself persisted/idempotent.
- Make startup, health, drain, restart, malformed JSONL, timeout, cancellation,
  unsupported SDK capability, and queue limits deterministic and auditable.

### Non-goals

- No direct experimental App Server CLI invocation or direct App Server JSON-RPC
  dependency, local App Server socket, arbitrary existing-TUI attachment, peer
  injection into a foreign session, undocumented private database/UI access,
  plugin patch,
  WebSocket/Remote Control/MCP production route, Reflex `429` observation,
  generic IR, group, files, commands, Web3, or other-harness adapter.

### Acceptance conditions

- A locked Python/SDK/runtime tuple starts/resumes a companion-owned thread,
  submits one peer text through JSONL, returns exactly the SDK's terminal
  `final_response`, and never scrapes intermediate output or tool events.
- The final response travels only from Python JSONL to Rust/T3, where it is
  encrypted and durably persisted before relay submission; a relay fixture sees
  ciphertext only. A successful response retry reuses its persisted
  `delivery_id` and never regenerates a different ciphertext.
- Fake-bridge and real-SDK tests prove same-ID/same-text idempotency, same-ID/
  different-text `idempotency_conflict`, no second Codex input, deterministic
  failure statuses, and no automatic replay after uncertain dispatch.
- The bridge rejects unknown/malformed JSONL fields, oversized input, and any
  thread ID/path/credential/file/command/tool field. It never emits a real
  Codex thread ID or workspace path to relay-facing code or audit.
- Integration tests cover process startup, SDK start/resume, health, bounded
  queues, final-response extraction, timeout/interrupt, cancellation, malformed
  JSONL, crash/restart, and shutdown without a user's arbitrary TUI.
- The Rust bridge implementation compiles independently against T0's stable
  `CodexEndpoint` façade; T0's client root module declaration is not edited by
  T5.
- The report identifies stable SDK evidence and exact support tuple; it does
  not claim native plugin support, arbitrary TUI attachment, or E2EE.

### Risks

- The Python runtime and SDK tuple add a packaging/support surface; an SDK
  change or missing `final_response` must fail closed rather than fall back to
  experimental App Server calls.
- A crash after turn dispatch leaves an unknown outcome. The design chooses no
  duplicate Codex input over automatic replay and requires explicit new-message
  retry semantics.
- Process supervision and local plaintext handoff are endpoint trust concerns;
  the relay must never become involved in them.

### Dependencies

T0 workspace ownership, T3 channel/client state and `RelayTransport`, T4 local
endpoint configuration, and ADR 0003's stable Python SDK route. The exact
Python/SDK/runtime pin, license evidence, fake-bridge contract, and real-SDK
revalidation are mandatory. T5 does not edit Cargo manifests; Rust dependency
requests go through the owning T3/T0 integration process.

### File ownership

`crates/client/src/bridge/**`, `crates/client/src/codex_jsonl/**`,
`crates/cli/src/codex_bridge/**`, `bridge/python/**`,
`bridge/pyproject.toml`, and bridge tests/fixtures under those directories.
T5 owns no Cargo manifest, root `Cargo.lock`, pairing CLI files, protocol,
relay, crypto, or client-secret-store files.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the Codex bridge engineer. Implement only T5 and follow ADR 0003.
> Keep the core Rust-first: supervise one long-lived locked Python bridge over
> restricted JSONL v1, and use only stable public `openai-codex`
> `AsyncCodex`/`thread_start`/`thread_resume`/`AsyncThread.turn` and terminal
> `TurnResult.final_response`. Never invoke the experimental `codex app-server`
> CLI directly or direct JSON-RPC App Server methods; the stable SDK's
> transitive runtime is allowed but is not a Telegraph API. Also reject
> caller-controlled commands, tools, cwd, model, approval, or other execution
> fields. Never use WebSocket, MCP, Remote Control,
> private DB/UI internals, or an arbitrary TUI. Keep real thread/workspace data
> inside the bridge-local endpoint store. Return final_response only to Rust;
> pass it through T3 for encrypted, state-before-send peer reply and persisted
> `delivery_id`, never to relay plaintext. Test same-ID/same-text idempotency,
> same-ID/different-text `idempotency_conflict`, duplicate failure semantics,
> no second Codex turn, known timeout/cancel, and no automatic replay after
> `turn_outcome_unknown`; explicit retry requires a new message ID. Touch only
> T5-owned files, do not edit Cargo manifests or root lock, run fake-bridge and
> real-SDK tuple tests, and report exact versions/licenses/limitations. Never
> claim E2EE.

## T6 — Two-peer integration, crash, and performance tests

### User flow

Two isolated clients pair against a disposable relay with one client offline
for part of the flow. A unique text message is stored, delivered once, locally
accepted, replied to, and audited. Replays, invalid identities, expiry, relay
failure, process crash, and resource floods produce bounded failures.

### Scope

- Build disposable test fixtures for two equal clients, opaque endpoints,
  `relay-a`-like SQLite, and the documented companion bridge stub.
- Execute R4 positive/negative acceptance vectors: pairing substitution and
  safety mismatch, code lifecycle/rate limits, offline TTL, out-of-order and
  duplicate delivery, transport-vs-E2E receipt separation, endpoint/channel
  isolation, crash ordering, rollback/rotation/revocation, prekey exhaustion,
  public/private prekey reserve-consume-burn-reconcile, both-side confirmation
  completion, delivery-id conflicts, and relay metadata/plaintext boundary.
- Exercise the bridge `final_response` return path through T3 encryption and
  persisted outbound delivery, including duplicate success, known failure, and
  `turn_outcome_unknown` semantics without a second Codex turn.
- Run the ADR performance budget and memory/body/queue bounds under repeatable
  local load; add property/fuzz tests for bounded CBOR and idempotency where
  useful.
- Measure the exact 65,536-byte ciphertext and 69,632-byte complete outer-CBOR
  envelope limits at client and relay boundaries; test one byte over each
  limit before storage or expensive decode.
- Produce redacted evidence with toolchain, fixture versions, commands, exit
  codes, and measured results.

### Non-goals

- No production deployment, real user credentials, server address, dashboard,
  group, attachment/file, command, Web3, generic IR, or new protocol behavior.
- Tests do not turn a passing vector into an E2EE certification; independent
  review remains required.

### Acceptance conditions

- A clean run proves exactly two equal clients can exchange a unique text and
  reply through separate machines/process fixtures, including offline relay
  storage and retry.
- Every R4 vector has pass/fail evidence, and any failure blocks release rather
  than being reclassified as an expected limitation.
- No replay creates a second Codex input; no cross-channel/endpoint injection
  succeeds; no relay fixture can read plaintext or forge an E2E receipt.
- A bridge final response is never written as relay plaintext; duplicate
  success/failure outcomes are stable and an uncertain turn is not replayed.
- A duplicate `delivery_id` with identical payload is idempotent; the same ID
  with changed ciphertext, size, expiry, or version returns
  `idempotency_conflict` and leaves the original row unchanged.
- Crash tests around the second confirmation report prove one SQLite
  transaction contains both-side completion plus code/pairing,
  pre-confirmation, and public-prekey-reservation tombstones; retry after a
  committed crash returns consumed and never reopens material.
- Performance results record p95/p99 service time, throughput, RSS, queue
  bounds, and test hardware against ADR targets.
- Evidence contains no raw keys, codes, plaintext, thread/workspace IDs, IPs,
  or unredacted logs.

### Risks

- In-memory fakes can hide SQLite crash or process-boundary bugs; use real
  SQLite WAL and separate client processes for the critical vectors.
- Timing-sensitive rate-limit/security tests can be flaky; use controlled
  clocks where safe and record the test method.

### Dependencies

T1, T2, T3, T4, and T5, plus ADR 0002's independent-review disposition and
ADR 0003's stable SDK support tuple. The test task may block on any unresolved
profile or route decision and must report the blocker precisely.

### File ownership

`tests/integration/**`, `tests/property/**`, `tests/performance/**`, test-only
fixtures under `tests/fixtures/**`, and redacted test evidence under
`docs/evidence/implementation/**` after implementation authorization.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the integration and performance test engineer. Implement only T6.
> Exercise two isolated equal clients with real SQLite WAL, a disposable
> opaque relay, offline delivery, the companion bridge stub, and the full R4
> positive/negative vectors: code races/expiry, transcript/key substitution,
> replay/order/dedup, receipt separation, endpoint/channel isolation,
> crash-before-send and crash-before-handoff, rollback, rotation/revocation,
> prekey reserve/consume/burn/reconcile, both confirmation-complete reports,
> delivery-id same-payload idempotency and changed-payload
> `idempotency_conflict`, final_response-through-T3 encryption, duplicate
> failure, and metadata/plaintext boundaries. Measure the ADR
> exact 65,536-byte ciphertext and 69,632-byte complete outer-CBOR bounds,
> throughput, p95/p99, memory, body, and queue budgets. Touch only T6-owned
> files; do not add product behavior, generic IR, dashboard, groups, files,
> commands, Web3, credentials, addresses, or unredacted evidence. Record
> reproducible commands, versions, exit codes, redacted results, and blockers.
> A green test run is not an E2EE claim; leave that decision to T8.

## T7 — Relay-a deployment and operational hardening

### User flow

An operator installs one relay binary as logical `relay-a`, supplies secrets and
TLS material through the runtime environment/secret store, initializes a WAL
database volume, checks health/readiness, observes redacted metrics, restarts
the process safely, and verifies TTL/backup/restore behavior without exposing
plaintext or committing an address.

### Scope

- Provide reproducible build/package instructions for the relay binary and
  least-privilege service configuration.
- Configure HTTPS/rustls certificate/key injection, body/connection/time limits,
  SQLite WAL volume, checkpoint/expiry maintenance, backup/restore procedure,
  filesystem permissions, resource limits, and graceful shutdown.
- Document health/readiness and minimal redacted metrics/log collection,
  rotation/retention, incident handling, and a rollback/repair runbook.
- Use a logical `relay-a` label only; resolve the actual endpoint at deployment
  time through an uncommitted operator mechanism.

### Non-goals

- No committed production hostname/IP, certificate, credential, `.env`, cloud
  account, dashboard, cluster, autoscaling, PostgreSQL migration, Web3,
  cross-harness service, group, files, commands, or remote execution.
- No operational document that calls transport acks E2E receipts or claims
  metadata anonymity.

### Acceptance conditions

- A clean staging install starts with no repository secrets, passes health and
  readiness, serves HTTPS with rustls, and survives graceful/abrupt restart
  without reopening expired/consumed pairing state.
- Resource/body/connection limits and SQLite backup/restore/expiry jobs are
  tested; permissions prevent unrelated users from reading the database/TLS
  material.
- Logs/metrics contain only redacted opaque IDs and approved operational
  counters; no plaintext, raw codes, keys, workspace data, IP, or real thread
  ID is present by default.
- The runbook names only `relay-a`; automated checks fail if a production
  address, token, or private key is present.
- The task records staging measurements and outstanding scale limits rather
  than implying cluster readiness.

### Risks

- TLS and secret-store mistakes can turn a sound relay boundary into a secret
  leak; use external injection and negative scans.
- SQLite backup/checkpoint/restore can violate expiry or rollback assumptions;
  test the exact operational sequence and fail closed on uncertain restore.

### Dependencies

T2 and T6. T8 must independently review release evidence before a production
  deployment or security claim.

### File ownership

`deploy/**`, `ops/**`, `scripts/deploy/**`, service/container/package files,
and deployment/runbook documentation under `docs/operations/**`. Do not edit
implementation crates or commit secrets.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the operations engineer. Implement only T7. Create a reproducible,
> least-privilege staging deployment for one logical `relay-a` using the
> existing Rust/Axum/rustls relay and SQLite WAL. Inject TLS/secrets only at
> runtime, configure body/connection/resource limits, graceful shutdown,
> checkpoint/expiry maintenance, backup/restore, health/readiness, and
> redacted logs/metrics. Never write an IP, production hostname, credential,
> token, private key, cookie, or `.env` to Git. Do not add a cluster,
> dashboard, Web3, generic IR, groups, files, commands, or other harnesses.
> Touch only T7-owned files, run secret scans and restart/expiry/backup tests,
> report exact staging measurements and scale limits, and make no E2EE claim.

## T8 — Independent security and release review

### User flow

Before a release or production `relay-a` deployment, an independent reviewer
receives the pinned source, protocol/profile evidence, test results, route
evidence, dependency/license data, threat model, and operational runbook. The
reviewer can reproduce the critical vectors, list blockers, and issue a
disposition without changing implementation code.

### Scope

- Independently review T0–T7 against R1, R4, ADR 0001, ADR 0002, ADR 0003,
  product contracts, and the prohibited-claims list.
- Verify the exact crypto profile/provider/immutable commit/license/support
  posture, deterministic transcript/MAC construction, secure persistence and
  rollback/rotation/repair, endpoint binding, receipt separation, relay
  plaintext boundary, rate limits/TTL/idempotency, Codex companion route,
  stable SDK `final_response` encryption return path, duplicate/unknown-turn
  failure semantics, secret/address hygiene, and performance/observability
  evidence.
- Review every workspace and crate `Cargo.toml`, the single-owner root
  `Cargo.lock` merge process, `rust-toolchain.toml`, CI/toolchain pins, Python
  bridge lock/runtime tuple, and direct/transitive dependency licenses for
  ownership conflicts, reproducibility, and unsupported defaults.
- Re-run selected positive/negative vectors and review the complete evidence
  chain, including toolchain versions and redaction.
- Produce an independent disposition: pass, pass with explicit conditions, or
  reject/block; enumerate owners and closure evidence for every condition.

### Non-goals

- No source edits, dependency substitutions, protocol redesign, generic IR,
  dashboard, group/file/command/Web3 work, or authorization by implication.
- No claim of E2EE, native existing-TUI support, metadata hiding, or availability
  unless the reviewed evidence directly supports that narrow claim.

### Acceptance conditions

- The review is performed by an independent reviewer who did not author the
  implementation tasks and records identity, date, source commit, commands,
  exit codes, and evidence status.
- Every R4 blocking condition is marked closed with evidence or remains an
  explicit blocker. The reviewer confirms that the relay cannot receive
  plaintext/key/session operations and that transport acks do not advance E2E
  receipt state.
- The review checks prohibited artifacts (real addresses, secrets, keys,
  plaintext, thread/workspace IDs) and confirms the companion route limitation.
- A release recommendation is unambiguous; “accept with conditions” does not
  authorize production claims until conditions are closed.

### Risks

- A checklist review can miss integration or persistence flaws; require
  source-level sampling, reproducible tests, and adversarial negative vectors.
- Pressure to call a conditional design “E2EE” or “production ready” can turn
  unresolved evidence into a security claim; keep the claims ledger explicit.

### Dependencies

T0 through T7, the closed product route decision, and all R4 profile/license/
support approvals. This task is review-only and must remain independent.

### File ownership

Read-only access to all implementation files; after a separately authorized
review, write only an independent report under `docs/reviews/**` and a claims /
evidence ledger under `docs/evidence/release/**`. Never modify source, ADR 0001,
or this task breakdown to make a result pass.

### Direct subagent prompt

> Execution parameters: `model: gpt-5.6-luna`; `reasoning_effort: xhigh`.
> You are the independent Telegraph security/release reviewer. Review only
> T8. Do not modify implementation, ADR, or task files. Inspect T0–T7, every
> crate manifest and root-lock ownership/merge record, the pinned Rust
> toolchain/CI, Python bridge lock/runtime tuple, and all direct/transitive
> license evidence. Inspect the pinned
> source and evidence for R1 companion-route limits, R4 exact protocol/provider
> and license/support decision, deterministic transcript and confirmation MAC,
> device/endpoints/channels, persistence/rollback/rotation/repair, relay
> ciphertext-only boundary, TTL/rate limits/idempotency, receipt separation,
> stable SDK `final_response` through T3 encryption, duplicate/unknown-turn
> failure semantics, Codex bridge behavior, secret/address hygiene, and
> performance/observability.
> Re-run selected positive and negative vectors, record source commit, commands,
> exit codes, and redacted evidence, then issue pass / pass-with-conditions /
> reject with explicit closure owners. Do not introduce generic IR, dashboard,
> groups, files, commands, Web3, or new crypto. Never claim E2EE or production
> readiness unless the evidence and approved claim policy directly warrant it.

## Execution order and handoff

The normal dependency order is:

```text
T0 -> T1 -> T2 -> T3 -> T4 -> T5 -> T6 -> T7 -> T8
```

T2 can be developed against opaque protocol fixtures before T3 is complete;
T4 can test pairing without T5; and T6 can run a bridge stub, but those are
test seams, not permission to bypass dependencies in a release. T8 is always
last for a release candidate and must independently re-check any changed
dependency, protocol field, persistence behavior, or Codex route.

The handoff from each task must include: changed file list, tests and exact
commands, toolchain/dependency versions, measured limits, known blockers,
security-sensitive assumptions, and a statement of claims not established.
No task completion text may say “E2EE implemented” or “independent review
passed” unless T8's separately authorized evidence explicitly says so.
