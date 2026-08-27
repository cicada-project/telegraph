# T2 Store Core Independent Review — 2026-08-24

## Review identity and provenance

- Review recorded at: `2026-08-23T21:22:21Z` (UTC; `2026-08-24` in Asia/Shanghai).
- Independent reviewer canonical ID: `/root/final_review_t2`.
- Reviewer model / reasoning strength: `gpt-5.6-sol` / `xhigh`.
- Repository baseline HEAD: `329b5a7f7a43e0fd1604f218724f2d946045edb4`.
- Reviewed implementation state: T2 Store source was present in the local worktree and was **not committed** at review time. The baseline HEAD therefore does not identify the reviewed source by itself.
- Review mode: independent, read-only source review and isolated test execution. The reviewer did not implement or modify the Store source.

## Disposition

**ACCEPT — T2 Store core handoff only.**

This disposition permits the accepted Store core to be handed to the T0 integration owner. It does not authorize HTTP or root integration, T3b, release, deployment, or any E2EE claim. In particular, this evidence is not proof that product E2EE is implemented or verified.

## Verification matrix

The reviewed Store and Protocol files were copied to an isolated review directory, and SHA-256 comparison confirmed that the isolated inputs matched the corresponding worktree files when the checks completed. Rust and Cargo version `1.85.1` were used.

| Check | Result | Exit code / count |
| --- | --- | --- |
| `cargo fmt --manifest-path crates/store/Cargo.toml --check` | PASS | `0` |
| `cargo check --manifest-path crates/store/Cargo.toml --tests` | PASS | `0` |
| Store test suite, single-threaded | PASS | `44/44`, exit `0` |
| Store test suite, default concurrency | PASS | `44/44`, exit `0` |
| `cargo clippy --manifest-path crates/store/Cargo.toml --all-targets -- -D warnings` | PASS | `0` |
| Four targeted retention/budget/quota regressions | PASS | `4/4`, exit `0` |
| `git diff --check -- crates/store` | PASS | `0` |
| Repository `Cargo.lock` / crate-local lock inspection | PASS | no lock created or modified by review |

The four targeted tests were:

- `operation_and_fetch_receipt_expire_before_tombstone_becomes_eligible`
- `policy_retention_strictly_covers_every_natural_lifetime_and_overflow`
- `cleanup_uses_one_shared_thousand_item_budget_and_converges`
- `tombstone_quota_never_evicts_within_retention_and_reuse_waits_for_cleanup`

## Critical reviewed locators

- Shared maintenance budget, SQLite savepoint, `total_changes()` accounting, and rollback: `crates/store/src/relay_opaque/mod.rs:99-182`.
- Cleanup ledger probe and comparison with the real committed ledger delta: `crates/store/src/relay_opaque/mod.rs:1187-1227`.
- Strict policy relationship requiring tombstone retention to exceed operation retention: `crates/store/src/relay_opaque/mod.rs:242-247`.
- Tombstone quota trimming requires both expiry and elapsed retention, and otherwise fails closed: `crates/store/src/relay_opaque/mod.rs:2006-2058`.
- Cleanup deletes expired operation ledger entries and fetch receipts before considering tombstones: `crates/store/src/relay_opaque/mod.rs:2438-2466`.
- Final cleanup audit and committed-change accounting: `crates/store/src/relay_opaque/mod.rs:2503-2511`.
- Strict retention and checked-overflow regression: `crates/store/src/relay_opaque/tests.rs:997-1037`.
- Shared 1,000-change maintenance budget, trigger side effects, audit-ring pressure, and convergence regression: `crates/store/src/relay_opaque/tests.rs:1150-1237`.
- Tombstone quota, atomic failure, and reuse-after-retention regression: `crates/store/src/relay_opaque/tests.rs:553-632`.
- Exact retention boundary regression: `crates/store/src/relay_opaque/tests.rs:634-662`.

## Historical P1 closure confirmation

1. **Cleanup-budget P1 remains closed.** Cleanup uses one transaction-wide `MaintenanceBudget`; candidate mutations run under SQLite savepoints, and the budget is charged from actual `total_changes()` deltas, including linked terminalization, trigger effects, audit-ring changes, the final audit row, and the durable operation ledger. An over-budget candidate is rolled back. The mixed workload and trigger regression asserts `committed_changes <= 1000` on every pass and proves convergence.
2. **Tombstone-retention/quota P1 remains closed.** Tombstones are eligible for quota trimming only after both delivery expiry and tombstone retention have elapsed. If capacity cannot be recovered without removing a protected tombstone, the operation fails atomically and does not clear the live row. Same-ID and different-ID reuse, policy lowering, operation-ledger expiry before tombstone reuse, and cleanup-mediated reuse are covered by regression tests.

## Strict retention boundary

Policy validation rejects `operation_retention_secs >= tombstone_retention_secs`, so tombstone retention must be strictly longer. Cleanup uses `< now` for operation ledger and fetch-receipt expiry and evaluates tombstones only after those prerequisites have been drained. The boundary regression proves:

- At `t=111`, the fetch receipt, operation outcome, and tombstone still exist.
- At `t=112`, the expired fetch receipt and operation outcome are removed while the tombstone remains.
- At `t=113`, the tombstone becomes eligible and is removed.

Checked conversion and overflow paths reject invalid maximum-time configurations and calls with `u64::MAX` time instead of wrapping.

## Scope exclusions and follow-up TODO

- **TODO — source commit SHA:** the T0 integration owner must commit the accepted T2 Store inputs and record the resulting commit SHA here or in a successor evidence record. Until then, `329b5a7f7a43e0fd1604f218724f2d946045edb4` is only the pre-existing baseline, not the identity of the reviewed implementation.
- **TODO — evidence commit SHA:** record the commit containing this evidence document after it is committed through the authorized Git workflow.
- HTTP/root integration, T3b crypto/client-state integration, full-system tests, release, and deployment require separate authorization and independent evidence.
- No R4 end-to-end security vector was established by this Store-only review. This document must not be used to claim that Telegraph currently provides E2EE, production security, or deployable product readiness.
