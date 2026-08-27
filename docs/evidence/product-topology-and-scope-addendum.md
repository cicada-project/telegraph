---
evidence_id: product-topology-and-scope-addendum-20260823
gate: product-contract
claim_ids:
  - PRODUCT-TOPOLOGY-001
  - PRODUCT-IDENTITY-002
  - PRODUCT-BOUNDARY-003
classification: inference
source_type: mixed-primary
source_locator: "README.md; SECURITY.md; docs/adr/0001-rust-first-mvp-architecture.md; docs/adr/0002-device-code-pairing-and-channel.md; docs/security/R4-telegraph-security-design.md"
source_version_or_commit: "Telegraph working tree; uncommitted (commit provenance TODO)"
accessed_at_utc: "2026-08-23T17:22:49Z"
reproduction:
  command: "read-only architecture consistency audit"
  exit_code: 0
  result_summary: "Existing product and security documents are consistent after the following scope clarification; no protocol change is proposed."
artifact_sha256: null
status: corroborated
reviewer: "/root/sol_review_t2_store"
review_disposition: ACCEPT
reviewed_at_utc: "2026-08-23T18:11:22.3849780Z"
provenance_todo: "After commit, replace source_version_or_commit with the actual commit ID; do not infer or pre-fill it."
security_claim: E2EE_not_claimed
---

# Product topology and scope clarification

This is a documentation addendum, not a new protocol decision, implementation
authorization, security certification, or E2EE claim. It makes the existing
ADR 0001/0002 and R4 boundaries explicit for implementation handoffs.

## Normative product invariants

- Every MVP channel has exactly two equal Codex CLI clients, A and B. The
  future Telegraph repository may contain those client components and an
  independently deployable central relay/mailbox server. Client and relay may
  run on different hosts, networks, and physical locations; `relay-a` is only
  a logical deployment name.
- One device or OS-user agent may own multiple local endpoints across multiple
  independent local workspaces and may form channels with multiple peers.
  Every endpoint-to-peer channel has exactly two participants and independent
  channel, ratchet, delivery, and audit state. This does not add shared or
  group-workspace semantics, and real thread/workspace identifiers remain
  client-local.
- `device_code` and `user_code` are short-lived, per-pairing-intent
  rendezvous/discovery inputs that guide an independent human safety-code or
  fingerprint verification. They are not device identity, peer
  authentication, encryption proof, or a long-term per-thread public-key
  directory/service.
- Public prekeys are bounded bootstrap metadata with explicit reservation,
  expiry, consumption, and burn/reconcile lifecycle. They are not a persistent
  public-key directory or a substitute for client-side identity verification.
- Peer plaintext E2EE remains the target design only. It is not implemented,
  verified, or claimable. Future Web3 work, if ever approved by a new ADR, is
  limited to a narrow transport/storage trait seam; no chain, wallet, token,
  consensus, or generic IR implementation is part of this product boundary.

## Handoff rule

An implementation task must preserve these invariants even when it handles only
opaque relay data or local client state. A passing build or transport
acknowledgement does not establish E2EE, peer authenticity, or a production
deployment.

The parent Cicada repository documents referenced by the R4 design are fixed
external inputs and are not files in this Telegraph checkout. Their locators
must not be silently treated as local implementation evidence.
