---
evidence_id: T3-provider-dependency-license-support-20260824
gate: T3-provider-dependency-license-support
claim_ids:
  - T3-PROVIDER-001
  - T3-DEPENDENCY-001
  - T3-LICENSE-001
  - T3-SUPPORT-001
classification: local-experiment
source_type: mixed-primary
source_locator: "vodozemac GitHub REST tag objects; crates.io vodozemac 0.10.0 API; immutable upstream Cargo.toml and LICENSE; local temporary-lock feature graph"
source_version_or_commit: "vodozemac 0.10.0; tag object edf362d46c64c63e94853ccaae2f34c7e73b892e; peeled commit bb39ec65357989f975e0d47f9fb35e0656180151"
accessed_at_utc: "2026-08-23T16:50:32Z"
observed_environment: "Windows PowerShell plus WSL; rustc 1.85.1; cargo 1.85.1; temporary non-authoritative crypto lock"
reproduction:
  command: "GitHub REST tag/ref queries; crates.io version API; temporary-copy cargo tree --locked queries listed below"
  exit_code: 0
result_summary: "provider identity and selected feature graph corroborated; ADR 0005 C1 accepted with conditions while checker enforcement and the dependency/license/support gates remain open"
artifact_sha256: null
status: accepted_with_conditions
gate_status: OPEN
disposition: ACCEPTED_WITH_CONDITIONS_C1
enforcement_status: PENDING_INDEPENDENT_REVIEW
reviewer: null
reviewed_at_utc: null
adr0005_decision: "C1 selected with conditions"
adr0005_decision_at_utc: "2026-08-23T20:03:26Z"
security_claim: E2EE_not_claimed
---

# T3 provider, dependency, license, and support gate

## Disposition

**ADR 0005 disposition: ACCEPTED WITH CONDITIONS — C1 SELECTED. Gate status:
OPEN.** This evidence identifies the selected provider release and the
currently resolved local feature graph, but it is not sufficient to close the
T3 dependency, license, or support gate. In particular, the repository root
lock does not yet include `telegraph-crypto`, the full transitive graph has not
passed `cargo-deny` or `cargo-audit`, no SBOM exists, and the C1 unified
`cbor4ii/serde1` risk still requires root-locked feature evidence and the
enforced source-policy checks.

This document is a read-only provider/dependency evidence report. It is not an
implementation acceptance, release approval, cryptographic proof, support
contract, or E2EE claim. T3 provider integration and all later T3 client-state
work still require independent review under
`docs/evidence/T2-T3-implementation-gate.md`.

## Immutable provider identity

| Item | Observation | Evidence status |
|---|---|---|
| Git annotated tag | `refs/tags/0.10.0` is a tag object with SHA `edf362d46c64c63e94853ccaae2f34c7e73b892e` | corroborated by GitHub REST |
| Peeled release commit | The annotated tag targets commit `bb39ec65357989f975e0d47f9fb35e0656180151` | corroborated by GitHub REST and the downloaded crate's `.cargo_vcs_info.json` |
| Registry release | crates.io version `0.10.0`, not yanked when observed | corroborated by crates.io API |
| Registry checksum | `b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b` | corroborated by crates.io API |
| Registry/source metadata | edition 2024, `rust-version = 1.85`, Apache-2.0 | corroborated by crates.io API and immutable upstream manifest |
| Telegraph direct selection | `vodozemac = { version = "=0.10.0", default-features = false }` | observed in `crates/crypto/Cargo.toml` |

Primary sources:

- [official vodozemac 0.10.0 release](https://github.com/matrix-org/vodozemac/releases/tag/0.10.0);
- [GitHub REST tag ref](https://api.github.com/repos/matrix-org/vodozemac/git/ref/tags/0.10.0) and [annotated tag object](https://api.github.com/repos/matrix-org/vodozemac/git/tags/edf362d46c64c63e94853ccaae2f34c7e73b892e);
- [immutable upstream manifest](https://raw.githubusercontent.com/matrix-org/vodozemac/bb39ec65357989f975e0d47f9fb35e0656180151/Cargo.toml) and [Apache-2.0 license text](https://raw.githubusercontent.com/matrix-org/vodozemac/bb39ec65357989f975e0d47f9fb35e0656180151/LICENSE);
- [crates.io 0.10.0 version API](https://crates.io/api/v1/crates/vodozemac/0.10.0) and [versioned Olm API documentation](https://docs.rs/vodozemac/0.10.0/vodozemac/olm/index.html).

The release page presents the annotated tag as signature-verified. This review
did not independently reproduce the GPG verification, so it records the
immutable tag/commit relationship but does not elevate GitHub's presentation
to an independent signature-verification claim.

## Features and unavoidable transitive dependencies

ADR 0005 now selects C1 with conditions. The repository checker at
`.github/scripts/check_cbor4ii_serde1.py` parses every existing crate manifest,
resolves aliases and workspace inheritance by actual package identity, permits
only the `telegraph-crypto` edge to request `serde1`, and rejects non-crypto
provider dependencies and source use. This is policy enforcement, not Cargo
feature isolation. The checker implementation and enforcement disposition are
**PENDING INDEPENDENT REVIEW**. The current protocol-only workspace does not
have a root-unified `serde1` graph; CI must report that state as pending rather
than presenting it as unified-feature evidence.

The immutable upstream manifest declares these optional features:
`default = ["libolm-compat"]`, `js`, `libolm-compat`,
`insecure-pk-encryption`, `experimental-session-config`, and `low-level-api`.
The temporary-lock inverse feature graph showed no vodozemac optional feature;
therefore the current direct manifest did not enable `libolm-compat`,
`experimental-session-config`, `low-level-api`, or `js`. This observation must
be repeated against the T0-owned root lock before integration.

Disabling default features does not remove all serialization dependencies.
The upstream manifest lists `matrix-pickle` and `serde_json` as unconditional
normal dependencies. The Rust 1.85-compatible temporary resolution selected:

- `matrix-pickle 0.2.3`, solely through `vodozemac 0.10.0`;
- `serde_json 1.0.151`, solely through `vodozemac 0.10.0`.

These are provider transitives, not permission to introduce a Telegraph JSON
wire format or generic intermediate representation. They require explicit
license/advisory/source accounting in the root locked graph.

The current crypto manifest also directly enables
`cbor4ii 1.2.2` feature `serde1`, which activates `serde` and `use_alloc`.
Current code uses that path for private provider pickle serialization, while
schema-specific `cbor4ii::core` remains present for fixed Telegraph records.
Nevertheless, ADR 0004 explicitly selected `default-features = false` with no
`serde1`, `use_alloc`, or `use_std`. A code-local restriction is not authority
to revise that ADR. The provider/dependency gate therefore remains rejected
until either:

1. the `serde1` dependency is removed and the ADR baseline is met; or
2. an authorized ADR deviation narrowly permits provider-state-only Serde,
   records the transitive/size/security impact, and is independently reviewed.

No conclusion in this section establishes canonical Telegraph wire encoding;
that remains a separate schema/vector gate.

## License and support limits

The fixed vodozemac crate declares Apache-2.0 and the immutable repository
contains the corresponding license. This closes only the provider crate's
declared-license identity. It does not close the licenses or notices of the
103-package temporary all-target resolution, including `matrix-pickle` and
`serde_json`; no authoritative `cargo-deny` report has been produced.

The upstream [security policy](https://github.com/matrix-org/vodozemac/security/policy)
provides a vulnerability-reporting address and points to Matrix's disclosure
policy. It does not state a response-time, maintenance-duration, patch-window,
or availability SLA. The Apache-2.0 license supplies the software without a
warranty; it is not a commercial support commitment. Therefore this evidence
establishes a reporting route but **does not establish a support SLA or a
minimum supported lifetime**.

[RUSTSEC-2024-0354](https://rustsec.org/advisories/RUSTSEC-2024-0354.html)
records an older vodozemac issue as affecting versions before 0.7.0; 0.10.0 is
outside that published affected range. This single advisory lookup is not a
substitute for a dated `cargo audit` over the authoritative root lock.

## Gate matrix

| Gate item | State | Reason / required closure |
|---|---|---|
| Exact provider release, tag object, peeled commit | CLOSED as identity evidence | Two official GitHub REST objects agree; registry source metadata points to the same commit |
| crates.io checksum, yanked state, license, MSRV | CLOSED as point-in-time metadata | Exact 0.10.0 API record captured |
| Exact direct version and default-feature disablement | CLOSED as manifest observation | `crates/crypto/Cargo.toml` exact-pins 0.10.0 and disables defaults |
| Forbidden vodozemac optional features absent | CLOSED only in temporary graph | Must be repeated with `--workspace --locked` after T0 integration |
| Unconditional `matrix-pickle`/`serde_json` identification | CLOSED as graph observation | Both paths are enumerated; their license/advisory closure remains open |
| `cbor4ii/serde1` compliance with ADR 0004 | OPEN / C1 ENFORCEMENT PENDING | ADR 0005 selects the narrow C1 exception; independent checker review, root-locked unified-feature evidence, and source-policy enforcement remain required |
| Authoritative root `Cargo.lock` | OPEN | Root workspace excludes crypto and its lock currently resolves only the delivered protocol crate |
| Complete license/source policy | OPEN | `cargo deny check` not run against an integrated root lock |
| Advisory closure | OPEN | `cargo audit` not run against an integrated root lock and dated RustSec DB |
| SBOM and dependency-weight baseline | OPEN | No CycloneDX SBOM or reviewed unique-package/feature delta exists |
| Upstream support assurance | OPEN | Reporting route exists, but no SLA or minimum maintenance term was found |
| Independent implementation/security review | OPEN | This report is evidence intake, not an acceptance review |

## Exact reproduction

The following PowerShell commands reproduced the official tag and registry
metadata with exit code 0 at the access time above:

```powershell
$ref = Invoke-RestMethod -Uri 'https://api.github.com/repos/matrix-org/vodozemac/git/ref/tags/0.10.0'
$tag = Invoke-RestMethod -Uri ("https://api.github.com/repos/matrix-org/vodozemac/git/tags/" + $ref.object.sha)
$ref.object.type
$ref.object.sha
$tag.object.type
$tag.object.sha
(Invoke-RestMethod -Uri 'https://crates.io/api/v1/crates/vodozemac/0.10.0').version |
  Select-Object num,checksum,crate_size,created_at,yanked,license,rust_version,edition
```

Direct Git transport was also attempted:

```text
git ls-remote https://github.com/matrix-org/vodozemac.git refs/tags/0.10.0 'refs/tags/0.10.0^{}'
```

It exited nonzero in the observed environment because the local TLS chain
contained an untrusted self-signed certificate. TLS verification was not
disabled; the successful official GitHub REST results above were used instead.

The dependency graph was reproduced without writing a crate-local or root lock
by copying only the crypto crate to a disposable WSL directory:

```bash
mkdir /tmp/telegraph-t3-evidence-20260824
cp -a crates/crypto /tmp/telegraph-t3-evidence-20260824/crypto
cd /tmp/telegraph-t3-evidence-20260824/crypto
rustc --version
cargo --version
timeout 180s cargo generate-lockfile
cargo tree --locked -e features -i vodozemac
cargo tree --locked -i serde_json
cargo tree --locked -i matrix-pickle
cargo tree --locked -e features -i cbor4ii
find ~/.cargo/registry/src -path '*/vodozemac-0.10.0/.cargo_vcs_info.json' -print -exec sed -n '1,80p' '{}' \;
```

Observed tool versions were `rustc 1.85.1` and `cargo 1.85.1`; the temporary
lock resolved 103 packages. That lock is disposable and **not** T0 integration
or release evidence.

After T0 accepts the manifest handoff, the authoritative gate must be rerun
from a clean checkout without changing the root lock during the checks:

```bash
cargo metadata --locked --format-version 1
cargo tree --workspace --all-targets --locked -e features
cargo tree --workspace --all-targets --locked -i vodozemac
cargo tree --workspace --all-targets --locked -i matrix-pickle
cargo tree --workspace --all-targets --locked -i serde_json
cargo deny check
cargo audit
```

The same reviewed root lock must then be used to generate and archive the
CycloneDX SBOM, dependency-weight count, license/source report, dated RustSec
result, and feature graph. Until those artifacts and the `cbor4ii/serde1`
decision are independently accepted, this gate remains **OPEN / REJECT**.
