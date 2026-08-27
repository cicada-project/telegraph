---
evidence_id: T3-crypto-core-v4-independent-review-20260823
gate: T3-crypto-core
claim_ids:
  - T3-CRYPTO-CORE-V4-001
  - T3-CRYPTO-CORE-V4-002
  - T3-CRYPTO-CORE-V4-003
classification: independent-review
source_type: mixed-primary
source_locator: "crates/crypto/Cargo.toml; crates/crypto/src/**; docs/adr/0002-device-code-pairing-and-channel.md; docs/adr/0004-rust-dependency-and-build-baseline.md; docs/security/acceptance-vectors.md; local vodozemac-0.10.0 source"
source_version_or_commit: "HEAD 329b5a7f7a43e0fd1604f218724f2d946045edb4; crypto source is current uncommitted working tree (commit provenance TODO)"
accessed_at_utc: "2026-08-23T19:10:56Z"
observed_environment: "WSL; Rust 1.85.1; cargo 1.85.1; crypto-only isolated temporary workspace"
reproduction:
  command: "cargo fmt --manifest-path <isolated>/Cargo.toml --all -- --check; cargo check --manifest-path <isolated>/Cargo.toml --all-targets --locked; cargo test --manifest-path <isolated>/Cargo.toml --all-targets --locked -- --test-threads=1; cargo clippy --manifest-path <isolated>/Cargo.toml --all-targets --locked -- -D warnings; cargo doc --manifest-path <isolated>/Cargo.toml --no-deps --locked; cargo metadata --manifest-path <isolated>/Cargo.toml --format-version 1 --locked --no-deps; cargo tree --manifest-path <isolated>/Cargo.toml --locked -e features"
  exit_code: 0
  result_summary: "fmt, check, clippy, doc, metadata, and tree passed; all 31 crypto tests passed single-threaded. A temporary lock was used only in the isolated copy and is not repository evidence."
artifact_sha256: null
status: corroborated
reviewer: "/root/implement_t0_scaffold"
review_disposition: ACCEPT
reviewed_at_utc: "2026-08-23T19:10:56Z"
provenance_todo: "After commit, replace source_version_or_commit with the actual commit ID; do not infer or pre-fill it."
security_claim: E2EE_not_claimed
---

# T3 crypto core v4 independent review

## Disposition and scope

The independent disposition is **ACCEPT for the crypto core only**. This record
reviews the current uncommitted `crates/crypto` implementation against the
T3/ADR requirements. It is not an integration, release, dependency-support,
or security certification decision. No code, Cargo manifest, or lockfile was
changed by this review.

The core remains a narrow vodozemac Olm v1 adapter. It does not implement or
claim E2EE, pairing UX, HTTP, relay, client, CLI, bridge, deployment, or T3b
local secret/audit storage behavior.

## Verified invariants

- `crates/crypto/src/account.rs:1271-1346` parses the complete pinned
  vodozemac `AccountPickle` one-time-key schema: private keys, unpublished
  public mapping, derived published status, exact lengths, sorted unique IDs,
  duplicate public-key rejection, and official secret-to-public derivation.
  Temporary secret material is held in `Zeroizing` storage. The local
  vodozemac 0.10.0 source confirms that `public_keys` is the unpublished map
  (`one_time_keys.rs:30-31,167-179`).
- `account.rs:1349-1375` and `tests.rs:216-241` reject provider/inventory
  mismatches, including same-identity published-key substitution with a
  recomputed structural binding.
- `account.rs:1489-1648` retains a bounded maximum-50 proof chain. Each proof
  signs profile, account state version, identity keys, sequence, previous
  canonical digest, published snapshot, and used-wire history digest. Tests
  cover tamper, truncation, reordering, insertion, duplicate sequence, fork,
  and chain-cap rejection.
- `tests.rs:400-444` confirms v2/v3 migration accepts only never-used empty
  accounts and rejects key-bearing legacy state.
- Account/session opaque state, provider pickle boundaries, fallback rejection,
  OTK total limit 50, published-only consumption, reuse/mapping checks,
  transactional failure no-advance behavior, 16 KiB plaintext and 65,536-byte
  message limits, CBOR bounds, record AAD/HKDF/XChaCha construction, invalid
  authentication budget, and zeroizing plaintext/state holders passed the
  reviewed tests.
- `account.rs:124-166,582-592` documents and implements the honest rollback
  boundary: a complete authentic old record cannot be rejected by core-only
  validation; T3b must supply an externally monotonic anchor. The
  `AccountStateAnchor` API does not claim to provide monotonic persistence.
- Provider `AccountPickle`/`SessionPickle`, ratchet internals, raw secrets, and
  raw outbound construction are not exported. The crate explicitly denies an
  E2EE/product implementation claim in `src/lib.rs:1-14`.

## Minor follow-up

`account.rs:1180-1182` accepts CBOR tags and simple value 23 (`undefined`) in
the generic preflight scanner, while ADR0004 requires forbidden tag/float
representations to be rejected. The later schema-specific parser and
canonical re-serialization still reject these inputs on actual account/session
restore, so no accepted-state bypass was found. Tighten the preflight and add
direct negative tests before treating the scanner as fully strict.

## Open gates and handoff limits

The following remain open and are not closed by this ACCEPT:

- T0-owned root workspace membership and authoritative root `Cargo.lock`;
- cargo-deny, cargo-audit, SBOM, complete dependency license/source/advisory
  evidence, and vodozemac release/support evidence for the required immutable
  commit;
- the vodozemac-unconditional transitive `serde_json` deviation (Telegraph
  crypto has no direct `serde_json` use), plus the `cbor4ii` `serde1` internal
  provider-pickle exception;
- T3b typed outbound-bundle/client integration, OS secret storage, local audit
  store, durable external monotonic anchor, and crash/recovery integration;
- HTTP, relay/client behavior, CLI, bridge, deployment, and release work.

The crypto core may be handed to the T0 integration owner for dependency and
workspace gating only. This record does not authorize T3 overall integration,
HTTP/client implementation, or any E2EE claim.
