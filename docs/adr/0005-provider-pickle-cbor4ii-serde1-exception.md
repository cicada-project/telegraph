---
adr: 0005
title: Narrow cbor4ii serde1 exception for private provider pickle serialization
status: "Accepted with conditions — C1 selected"
decision: c1_selected_with_conditions
review_status: accepted_with_conditions
enforcement_status: pending_independent_review
implementation_authorization: unchanged
release_gate: open_pending
security_claim: E2EE_not_claimed
technical_owner_decision: "C1 selected; C2 retained only as a fallback"
decision_at_utc: "2026-08-23T20:03:26Z"
---

# ADR 0005: Narrow `cbor4ii/serde1` exception for private provider pickle serialization

- Status: **Accepted with conditions — C1 selected**
- Date: 2026-08-24
- Decision owner: Telegraph technical lead
- Technical-owner decision recorded at: `2026-08-23T20:03:26Z`
- Scope: serialization of vodozemac 0.10.0 `AccountPickle` and
  `SessionPickle` inside `telegraph-crypto`
- Selected path: **C1**, with the conditions and open evidence gates below
- Fallback path: **C2** remains available only if C1 enforcement is rejected or
  becomes unverifiable; C2 is not selected or implemented by this decision
- Security status: this proposal does not implement, verify, or authorize an
  E2EE or production-readiness claim

## Context and baseline deviation

[ADR 0004](0004-rust-dependency-and-build-baseline.md) selects cbor4ii 1.2.x
with `default-features = false` and explicitly excludes `serde1`, `use_alloc`,
and `use_std` from its schema-specific CBOR baseline. That remains the rule
for Telegraph protocol, transcript, relay, bridge, and public persistence
schemas.

The current `telegraph-crypto` provider adapter exact-pins vodozemac 0.10.0
with default features disabled. Vodozemac exposes its supported provider
state as typed `AccountPickle` and `SessionPickle` values. The current adapter
uses cbor4ii's `serde1` path to serialize and deserialize only those private
provider values. Enabling `serde1` also enables cbor4ii's `use_alloc` and
Serde integration, so this is a real feature-graph deviation from ADR 0004;
an implementation-local restriction cannot approve it by itself.

`telegraph-protocol` also directly depends on registry package
`cbor4ii 1.2.2`, although its manifest requests no optional cbor4ii feature.
Cargo unifies feature requests for one package ID across the resolved graph.
When protocol and crypto are integrated into one root lock, the one resolved
cbor4ii package is therefore compiled with the union that includes `serde1`;
the protocol dependency edge does not create a separately compiled core-only
cbor4ii instance. Saying that only crypto *requests* `serde1` does not create
technical feature isolation and does not make `cbor4ii::serde` unavailable to
other workspace crates. This proposal must explicitly accept and constrain
that unified surface under C1, or provide a separately reviewed package/code
boundary under C2.

The immutable provider identity, unavoidable `matrix-pickle` and
`serde_json` transitives, temporary feature-graph observation, and remaining
license/support gaps are recorded in the
[T3 provider/dependency gate](../evidence/T3-provider-dependency-license-support-gate.md).
That evidence identifies annotated tag object
`edf362d46c64c63e94853ccaae2f34c7e73b892e`, peeled commit
`bb39ec65357989f975e0d47f9fb35e0656180151`, and crates.io checksum
`b98bf83c0992966775b8012f194b07b44928996163e5a05b741b43891571ae5b`.
That gate remains **OPEN / REJECT**. The
[crypto-core v4 independent review](../evidence/T3-crypto-core-v4-independent-review-20260823.md)
records **ACCEPT for the crypto core only** at its reviewed uncommitted
snapshot, with commit provenance still TODO. Its CBOR-scanner minor has since
received a directed code fix and local account/session negative tests, but
that delta still requires the original reviewer's targeted disposition. None
of this closes the feature-unification, provider, root-lock, license, support,
T3b, or release gates.

This ADR proposes how to reconcile the feature deviation. It does not modify
the implementation authority in the
[T2/T3 implementation gate](../evidence/T2-T3-implementation-gate.md), and it
does not authorize T4 or later work.

## Decision drivers

The decision must:

1. use vodozemac's public, typed pickle API instead of extracting or
   inventing provider ratchet state;
2. keep attacker-controlled or corrupted state behind strict byte, nesting,
   item, collection, and schema bounds before Serde can allocate;
3. prevent private provider bytes from becoming a Telegraph wire format,
   public API, log field, relay field, or generic intermediate representation;
4. preserve the exact provider version/schema review boundary and fail closed
   on schema drift;
5. keep private state within the opaque, zeroizing, storage-AEAD boundary;
6. retain a small dependency and maintenance surface compatible with Rust
   1.85.1; and
7. leave dependency, license, advisory, support, SBOM, rollback, and E2EE
   gates explicit rather than treating a green crypto test suite as closure.

## Options considered

### A. Fork vodozemac to expose a bounded provider-state codec

Maintain an immutable Telegraph fork that exposes a dedicated bounded
serialization API without cbor4ii `serde1` in Telegraph's direct graph.

Advantages:

- the allocation and schema boundary could live next to the provider types;
- Telegraph could call a purpose-built API rather than a generic Serde codec.

Costs and risks:

- Telegraph would own a security-sensitive cryptographic-provider fork,
  forward ports, release provenance, advisories, and compatibility testing;
- a fork weakens the benefit of exact upstream release pinning and increases
  the time to consume upstream security fixes;
- the fork would need its own immutable source, license, support, audit, and
  reproducible-build evidence.

Disposition: **not recommended for the MVP**. Reconsider only if upstream
cannot support the bounded public API and option C cannot meet its review
conditions.

### B. Use `matrix-pickle`, libolm compatibility, or an encrypted-pickle format

Enable vodozemac's default `libolm-compat` path, call lower-level pickle
machinery, or use a password/encrypted pickle as the adapter format.

Advantages:

- may resemble historical Matrix/libolm persistence formats;
- might appear to combine serialization and encryption in one operation.

Costs and risks:

- `libolm-compat` is explicitly outside the reviewed vodozemac feature set;
- `matrix-pickle` is already an unavoidable provider transitive, but that is
  not authority for Telegraph to call it directly or depend on its internal
  schema;
- a provider encrypted pickle does not replace Telegraph's reviewed
  record-AEAD AAD, key separation, nonce, rollback-anchor, or crash semantics;
- it adds legacy/schema/password-KDF behavior without eliminating the need
  for bounded preflight and opaque storage handling;
- lower-level/private provider state would increase version coupling and
  could expose secrets or create a second storage construction.

Disposition: **rejected**. Do not enable `libolm-compat`, call
`matrix-pickle` directly, publish provider pickle bytes, or substitute an
encrypted pickle for Telegraph storage AEAD.

### C. Constrain or isolate `cbor4ii/serde1` for private provider state

Allow typed vodozemac 0.10.0 `AccountPickle` and `SessionPickle`
serialization only after one of the following mutually exclusive closure
paths is independently accepted.

#### C1. Explicitly accept and police Cargo's unified feature surface

Accept that the single cbor4ii package ID is compiled with `serde1` for every
dependent workspace crate, while allowing only the crypto dependency edge to
request the feature and only crypto source to use the Serde module.

C1 requires all of the following, not merely a manifest comment:

- root-locked `cargo tree -e features` evidence proves that only the
  `telegraph-crypto -> cbor4ii` dependency edge requests `serde1`, while the
  evidence explicitly shows and acknowledges the unified package feature;
- CI source/dependency policy rejects `cbor4ii::serde`, generic Serde CBOR
  models, or provider-pickle types in every non-crypto crate;
- `telegraph-protocol` retains direct core Encode/Decode use and has
  workspace-integrated core-codec tests for canonical ordering, duplicate and
  unknown fields, non-shortest forms, forbidden types, bounds, and trailing
  bytes while cbor4ii is compiled with the unified feature set; and
- independent security review explicitly accepts that API availability is
  constrained by enforceable repository policy rather than Cargo isolation.

The technical owner selects C1 as the narrow path, subject to these conditions.
The C1 decision does not claim that the conditions are already evidenced: the
root-locked feature graph, independent security acceptance, and all common
supply-chain gates remain **OPEN** until their evidence is produced and
reviewed.

#### C2. Use a separately reviewed package ID or isolated codec

If security review does not accept C1, move provider-pickle serialization to
a separately reviewed codec boundary that does not unify with protocol's
cbor4ii package ID. Examples requiring their own review include a
purpose-built bounded provider-state codec or a renamed/forked package with a
distinct package identity and immutable source.

Renaming a Cargo dependency edge is not sufficient when it still resolves to
the same package ID. Silently selecting another cbor4ii version merely to
obtain duplicate packages is also prohibited. Any distinct package, version,
source, fork, or codec must be intentional in the root graph and receive
license, advisory, provenance, feature, dependency-weight, SBOM, compatibility,
and maintenance review before use.

No C2 implementation or evidence currently exists. C2 is retained as an
unselected fallback and remains **OPEN**.

Advantages:

- uses the provider's public typed pickle API without a provider fork or
  private ratchet-state extraction;
- keeps the intended use in one crate and one private storage boundary,
  subject to either C1 policy enforcement or C2 technical isolation;
- retains the existing schema-specific cbor4ii core path for Telegraph-owned
  canonical records and wire objects;
- has the smallest implementation and maintenance delta among viable options.

Costs and risks:

- adds Serde and allocation-capable codec APIs to the unified cbor4ii package,
  not only to a technically isolated crypto build;
- couples the preflight parser to the exact vodozemac pickle schema;
- requires root feature-graph, dependency-weight, license, advisory, and SBOM
  evidence that does not yet exist;
- an incorrect call order or overly permissive preflight could allow a
  corrupted state to allocate before rejection.

Disposition: **C1 selected with conditions; C2 retained as an unselected
fallback**.

### D. Replace the cryptographic provider

Select another audited provider with a naturally bounded persistence API.

Advantages:

- could remove this particular serialization mismatch.

Costs and risks:

- reopens the provider choice, compatibility profile, identity/prekey model,
  threat analysis, dependency and license review, test vectors, and R4
  security design;
- a different provider may introduce a larger or less mature dependency and
  support surface;
- it is disproportionate to a narrow private serialization exception.

Disposition: **deferred**. Any provider replacement must reopen R4 and the
provider/dependency gate through a new ADR; this proposal gives no authority
to substitute a provider.

## Decision: C1 selected with conditions

C1 is selected as the narrow exception path. It accepts Cargo's unified
`cbor4ii` feature surface as a repository-policy risk, not as crate-level
feature isolation. The exception supersedes only ADR 0004's `no serde1` and
implied `no use_alloc` rule for the exact private provider-pickle use in
`telegraph-crypto`; all other ADR 0004 CBOR, dependency, build, audit, and
release rules remain unchanged.

The C1 selection is conditional. It does not close the dependency, root-lock,
license, advisory, support, SBOM, T3b, or release gates and does not authorize
root integration before the required evidence is independently reviewed.

The intended provider-state use, if a closure path is accepted, is exactly:

- crate: `telegraph-crypto`;
- codec: either the C1 unified cbor4ii 1.2.2 package with only crypto's edge
  requesting `serde1`, or the separately reviewed C2 package/codec;
- provider: vodozemac 0.10.0 at the immutable release recorded by the T3
  provider evidence;
- values: vodozemac `AccountPickle` and `SessionPickle` only;
- direction: private provider-state serialization and restoration only;
- destination/source: opaque, locally authenticated-encrypted client state;
- lifetime: until a smaller supported upstream bounded API is reviewed or
  the provider/schema changes.

Under C1, Cargo technically exposes the unified cbor4ii feature surface to
other dependent crates; the restriction on use is intended to be a reviewed
and CI-enforced repository policy, not feature isolation. The narrow checker
at `.github/scripts/check_cbor4ii_serde1.py` parses every existing crate
manifest, recognises aliases by their `package = "cbor4ii"` identity, permits
only the `telegraph-crypto` edge to request `serde1`, and rejects non-crypto
Serde/provider source use. The checker implementation and its enforcement
remain **pending independent review**; no other type, feature, or data path
inherits permission to use provider Serde state. C2 would require a
separately reviewed technical boundary if this policy cannot remain
enforceable.

## Mandatory controls

### Bounded preflight before Serde

Every restored provider byte string must pass an allocation-free, bounded
generic CBOR preflight before any `cbor4ii::serde` or Serde deserializer is
called. At every nesting level the generic preflight must directly reject:

- every major-type-6 tag;
- major-type-7 float16, float32, and float64;
- `undefined` / simple value 23 and every simple value other than false,
  true, and null (20, 21, and 22);
- indefinite arrays, maps, byte/text strings, standalone `break`, and reserved
  additional-information values; and
- non-shortest integers or lengths, overflow, invalid UTF-8, trailing data,
  and inputs beyond the independent byte/depth/item/container bounds.

Account and session tests must inject each forbidden class directly into the
preflight/deserialization entry points and instrument that Serde has not been
called. Boundary tests must also retain valid provider-pickle parsing.

The account path must additionally enforce the exact pinned `AccountPickle`
field shape and canonical field order before Serde. It must:

- use only fixed-size stack state or allocations bounded independently of
  attacker-declared lengths;
- reject input above the account byte limit before parsing;
- reject duplicate, missing, unknown, reordered, or trailing fields and
  non-shortest CBOR integer/length encodings;
- for account state, validate all provider one-time-key IDs, key lengths,
  derived public-key mappings, published state, duplicates, ordering, and
  configured key-count bounds;
- fail closed on any account-schema difference, including a valid CBOR value
  that does not match the pinned provider schema.

The current `SessionPickle` path has only the allocation-free generic bounded
scanner followed by provider-typed deserialization and canonical
re-serialization equality. It does **not** currently have an independent,
schema-specific session-field validator before Serde. Whether that combination
is sufficient for the exact pinned session schema, or whether a dedicated
session validator is mandatory, remains an **OPEN acceptance item** for the
independent security reviewer. This proposal does not claim it is closed.

The directed crypto minor currently rejects tags, float16/32/64, undefined,
other unapproved simple values, indefinite/break, and the existing structural
invalid classes in both account and session preflight tests, with Serde-call
instrumentation. Its local 32-test result is implementation evidence awaiting
targeted independent review, not ADR acceptance.

Serialization of a typed provider value must apply an independent maximum to
the resulting byte string. The output buffer and any temporary private-key or
plaintext buffer must enter a zeroizing holder immediately on successful
creation, before length checks or other fallible work.

### Private opaque storage boundary

Provider serialization bytes must remain private implementation details:

- public APIs expose only opaque account/session state wrappers; they do not
  expose raw pickle bytes or a general serialize/deserialize hook;
- wrappers do not implement secret-revealing `Debug`, display, or unrestricted
  clone/conversion behavior;
- plaintext provider bytes are never logged, audited, included in an error,
  emitted as JSON, placed in a relay envelope, or sent over the peer wire;
- storage uses the separately reviewed record AEAD, domain-separated key
  derivation, fresh nonce, exact record AAD, and zeroizing plaintext holder;
- the relay receives neither provider state nor its storage keys; and
- a serde-derived provider representation is not a canonical Telegraph
  transcript or wire encoding. Telegraph-owned public/wire records continue
  to use fixed schema-specific codecs under ADR 0004.

### Exact dependency and feature boundary

- Vodozemac remains exact-pinned to 0.10.0 with default features disabled.
  `libolm-compat`, `experimental-session-config`, `low-level-api`, `js`, and
  other unreviewed optional features remain disabled.
- Under C1, cbor4ii remains exact-pinned to 1.2.2 and only the crypto
  dependency edge may request `serde1`. The implied `use_alloc` is part of
  the same unified package feature set, not a separate general allocation
  permission; `use_std` is not approved. CI and review must not describe this
  as crate-level feature isolation.
- Under C2, the distinct package/code boundary and exact accepted features
  replace the preceding C1 rule. A dependency alias that resolves to the same
  package ID, or an unreviewed second cbor4ii version, does not satisfy C2.
- `serde_json` remains an unconditional vodozemac transitive. Telegraph code
  currently does not call it in `telegraph-crypto` and must not start doing
  so, use it for provider state, or introduce JSON into peer/relay/storage
  formats. Source scans and the root graph must demonstrate that restriction.
- `matrix-pickle` remains an unconditional provider implementation
  dependency. Telegraph must not call its internal APIs or treat it as an
  approved direct persistence format.
- No raw provider pickle, generic Serde value, generic CBOR map/value, JSON
  value, or provider schema type may cross the crypto adapter boundary.
- Under C1, source-policy checks must reject `cbor4ii::serde` and Serde-backed
  CBOR models in every non-crypto crate, including protocol, even though the
  unified dependency technically exports those APIs.

### Root integration and supply-chain evidence

Before the C1 conditions can support a T0 handoff or release evidence, the
T0-owned root lock must include the crypto crate and the exact accepted
manifests. The conditional C1 selection itself does not change workspace
membership or the root lock.
Against that same clean lock, independent review must retain:

- `cargo metadata --locked --format-version 1` from the root manifest's natural workspace;
- normal and all-target `cargo tree --workspace --locked -e features` output,
  including inverse paths for vodozemac, cbor4ii, Serde, `serde_json`, and
  `matrix-pickle`;
- for C1, a feature-edge proof that only crypto *requests* cbor4ii `serde1`,
  an explicit record that the resulting package feature is unified, and CI
  source-policy plus protocol core-codec test evidence; or, for C2, proof of
  the reviewed distinct package ID/code boundary with no silent duplicate;
- a feature proof that the forbidden vodozemac features remain absent;
- `cargo deny check` license, advisory, ban, and source results;
- a dated `cargo audit` result using the authoritative root lock;
- a CycloneDX SBOM, notices, dependency-weight count, and delta from the
  reviewed baseline; and
- Rust 1.85.1 locked fmt/check/test/clippy/doc results plus the bounded
  preflight, schema-drift, storage-AEAD, and rollback tests.

A disposable crate-local lock or temporary graph may diagnose the feature
path, but it is not root integration or release evidence.

### Rollback boundary

Valid provider serialization and a valid internal proof chain cannot by
themselves distinguish a complete older authentic account/session record
from the current record. T3b must persist and compare the crypto state's
domain-separated digest through the independently monotonic external rollback
anchor required by ADR 0004 and ADR 0002. Missing, mismatched, rolled-back, or
unverifiable anchor state fails closed.

This exception does not relax the DB-first `PREPARED -> anchor CAS ->
ANCHORED/COMMITTED` recovery contract and does not claim protection against
simultaneous rollback of both encrypted state and the external anchor or a
compromised root endpoint.

## Re-review triggers

Any of the following invalidates this exception until a new independent ADR
review completes:

- a vodozemac version, source commit, registry checksum, feature, or provider
  substitution changes;
- `AccountPickle` or `SessionPickle` schema, field order, key representation,
  publication status, or canonical encoding changes;
- cbor4ii, Serde, `matrix-pickle`, or `serde_json` changes version, feature,
  source, or resolved dependency path;
- provider bytes become public, cross-process, relay-visible, wire-visible,
  JSON-visible, or accessible without the opaque wrapper and storage AEAD;
- any preflight limit, call order, schema check, zeroizing lifetime, record
  AEAD construction, or rollback-anchor contract changes;
- a new advisory, yanked release, license/source difference, unsupported
  MSRV, or upstream support-policy change is observed; or
- the root feature graph, deny/audit report, SBOM, or dependency budget no
  longer matches the reviewed evidence.

## C1 completion conditions and open gates

The C1 selection is accepted with conditions. Its exception and any T0
handoff remain conditional until independent evidence:

1. accepts Cargo's unified API surface plus the dependency
   edge, source-policy, and protocol core-codec CI controls; or, for C2,
   verifies the distinct reviewed package/code boundary;
3. verifies all forbidden CBOR classes reject in account and session before
   Serde, then decides the open question of whether `SessionPickle` requires
   an independent schema-specific validator;
4. records the directed crypto-minor review disposition and a committed source
   revision for the existing crypto-core ACCEPT evidence;
5. verifies the code uses Serde only after the accepted bounded preflight and
   only for the two typed provider pickle values;
6. verifies the opaque wrapper, zeroization, storage AEAD, source scans, and
   no-public-raw-provider-state boundary;
7. accepts the authoritative root locked feature graph and complete
   deny/audit/SBOM/license/advisory evidence; and
8. verifies the T3b external monotonic rollback-anchor integration.

## Gate matrix

| Item | Current state | Required closure |
|---|---|---|
| Cargo package-ID feature unification identified | CLOSED as a design fact | Retain explicit distinction between a requesting dependency edge and the unified package feature |
| C1 unified-surface risk acceptance | SELECTED WITH CONDITIONS / OPEN | Independent security acceptance plus root-locked edge proof, non-crypto source-policy enforcement, and protocol core-codec CI tests |
| C2 distinct package/codec isolation | UNSELECTED FALLBACK / OPEN | Reviewed distinct package ID or isolated codec/fork, with no alias-only claim or silent duplicate version |
| Account schema-specific preflight | ACCEPT at reviewed crypto-core snapshot | Record committed provenance and retain exact-schema/provider mapping tests |
| Generic tag/float/simple preflight minor | FIXED LOCALLY / REVIEW OPEN | Original reviewer must verify account/session negative matrix, Serde `(0, 0)` instrumentation, and valid-pickle controls |
| Session schema-specific validation | OPEN | Security reviewer must decide whether generic bounded scan plus typed/canonical provider validation is sufficient; implement a dedicated validator if required |
| Opaque wrapper, zeroization, record AEAD | ACCEPT at reviewed crypto-core snapshot only | Retain on the committed reviewed source and recheck after integration |
| Root feature graph and `Cargo.lock` | OPEN | T0 integration and independent locked graph review for the selected C1/C2 path |
| Deny, audit, licenses, support, SBOM, dependency budget | OPEN / REJECT | Complete authoritative root-lock evidence and review |
| T3b external monotonic rollback anchor | OPEN | Durable client-secret integration and crash/recovery review |
| ADR 0005 disposition | ACCEPTED WITH CONDITIONS — C1 SELECTED | All selected-path and common evidence gates above must close before integration or release evidence |

This conditional C1 decision covers only the narrow ADR 0004 feature
deviation. It does **not** by itself close:

- the authoritative root `Cargo.lock` and reproducible workspace gate;
- the full transitive license, notice, advisory, source, dependency-weight,
  or SBOM gate;
- upstream support/SLA uncertainty;
- T3b rollback-anchor implementation or client-secret integration;
- the R4 vectors, T4/T5/T6/T8, deployment, or release gates; or
- any E2EE, metadata-privacy, endpoint-security, or production-readiness
  claim.

Until those independent gates close, the T3 provider/dependency evidence
remains **OPEN / REJECT**, and Telegraph must not claim E2EE or production
readiness.
