---
evidence_id: T2-T3-implementation-gate-20260823
gate: T2-T3
claim_ids:
  - T2-T3-GATE-001
  - T2-T3-GATE-002
  - T2-T3-GATE-003
classification: independent-review
source_type: mixed-primary
source_locator: "docs/implementation/MVP-task-breakdown.md; docs/security/R4-telegraph-security-design.md"
source_version_or_commit: "ca37d28bed9a50b776b2f8f2d3396df771207186"
accessed_at_utc: "2026-08-23T13:00:24Z"
observed_environment: "Telegraph governance and implementation-gate documents; no implementation result"
reproduction:
  command: "independent T2/T3 implementation-gate review"
  exit_code: null
  result_summary: "T2 relay/store/API and T3 crypto/client-state authorized with conditions; T4/T5/T6+ blocked"
artifact_sha256: null
status: corroborated
reviewer: telegraph-t2-t3-implementation-gate-reviewer-01
reviewed_at_utc: "2026-08-23T13:00:24Z"
design_gate: authorize_with_conditions
implementation_authorization: t0_t1_t2_t3_owned_files_with_conditions
security_claim: E2EE_not_claimed
---

# T2/T3 implementation-gate evidence

## Disposition

This record is a subsequent implementation addendum. It extends permission for
owned T2/T3 implementation and tests without rewriting ADR 0001-0004 or the R4
design-review history; R4's gate-local `t0_t1_neutral_scaffold_only` metadata is
historical and does not conflict with this addendum.

The independent review by `telegraph-t2-t3-implementation-gate-reviewer-01` at
`2026-08-23T13:00:24Z`, against source commit
`ca37d28bed9a50b776b2f8f2d3396df771207186`, authorizes T2 and T3 **with
conditions**. This is an implementation-scope gate, not a release or security
certification. T4, T5, T6, T7, and T8 remain blocked, including CLI, bridge,
integration, release, deployment, and independent release review work.

The T0 integration owner may change root workspace membership, the root
`Cargo.lock`, and reserved crate-root glue only at an accepted handoff. T1
remains neutral framing. T2 and T3 may touch only their owned files below; no
cross-task, CLI, bridge, or deployment edits are authorized. Every result still
requires independent review. The 30 R4 acceptance vectors have not been
executed. E2EE is not implemented or verified, and no E2EE or production claim
is authorized.

## T2 — relay/store/API ownership and conditions

T2 owns only:

- `crates/store/Cargo.toml`;
- `crates/store/src/relay_opaque/**`;
- `crates/store/migrations/relay_opaque/**`;
- `crates/relay/Cargo.toml`;
- `crates/relay/src/**`;
- relay API tests under `crates/relay/tests/**`;
- non-secret store/API fixtures.

T0 retains `crates/store/src/lib.rs`,
`crates/store/src/migrations.rs`, the root workspace membership, and the root
lock. T2 owns no `store::client_secret` path and must not edit client, crypto,
CLI, bridge, or deployment files.

T2 conditions are the task breakdown's opaque relay boundary: SQLite WAL and
explicit crash-safe transactions; atomic pairing/prekey/completion lifecycle;
strict neutral framing, 65,536-byte ciphertext and 69,632-byte outer-envelope
limits; bounded body/resource use; idempotent delivery IDs and conflict results;
uniform code errors, rate limits, quotas, expiry/tombstones, and redacted
observability. The relay must not decrypt, generate keys, open sessions,
interpret Codex text, or store plaintext/private keys. Proposed 7-day message
and 10-minute pairing/user-code TTLs remain product-pending configuration, not
approved release defaults. T2 testing must not start a production relay.

## T3 — crypto/client-state ownership and conditions

T3 owns only:

- `crates/crypto/Cargo.toml` and `crates/crypto/src/**`;
- crypto test vectors under `crates/crypto/tests/**`;
- `crates/client/Cargo.toml`;
- `crates/client/src/state/**`;
- `crates/client/src/channel/**`;
- `crates/client/src/transport/**`;
- `crates/store/src/client_secret/**`;
- `crates/store/migrations/client_secret/**`.

T0 retains `crates/client/src/lib.rs`,
`crates/store/src/migrations.rs`, root workspace membership, and the root lock.
T3 owns no `store::relay_opaque`, relay, CLI, bridge, deployment, or T0 glue
files.

T3 conditions are the task breakdown and ADR 0002 profile requirements:
provider/dependency/license/support closure; isolated client-secret storage and
migration streams; atomic prekey reserve/consume/burn/reconcile; deterministic
transcript and confirmation handling; endpoint/channel isolation; bounded
replay/order and receipt semantics; state-before-send and state-before-handoff;
rollback, rotation, revocation, repair, and privacy-safe audit. Uncertainty
must fail closed. No custom cryptographic composition, unreviewed provider
substitution, production cryptographic claim, or E2EE claim is authorized.

## Evidence limits

This record does not report source changes, test passes, vector results, a
production deployment, E2EE, metadata privacy, or production readiness. It
records only the current conditional scope, ownership, and blockers. The full
acceptance vectors remain future requirements under R4 and T6/T8 review.
