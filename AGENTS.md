# Telegraph repository instructions

- The product route is approved (2026-08-23) as a lightweight Rust-first core with the stable SDK companion route in ADR 0003. R1, R4, and ADR 0001/0002/0003 have independent-review dispositions of **accept with conditions**; E2EE is not implemented, verified, or claimable.
- Current implementation authority is T0/T1 plus T2/T3 owned files under the independent authorize-with-conditions gate recorded in the subsequent implementation addendum `docs/evidence/T2-T3-implementation-gate.md`. This addendum extends implementation/test permission without rewriting ADR 0001-0004 or the R4 design-review history: R4's gate-local `implementation_authorization: t0_t1_neutral_scaffold_only` remains historical and does not conflict with the addendum. The T0 integration owner may change root workspace membership, `Cargo.lock`, and reserved crate-root glue only at an accepted handoff. T2/T3 may change only their owned files; cross-task edits are prohibited.
- T1 is neutral framing only. Do not freeze the reviewed crypto profile, provider-specific fields, or confirmation semantics in the neutral scaffold.
- T2 relay/store/API and T3 crypto/client-state work remain conditional on their recorded ownership and closure conditions. T4/T5/T6+ work, including CLI, bridge, integration, release, and deployment, remains blocked pending a later gate. Every result requires independent review; the 30 R4 vectors have not been executed, and no result may claim E2EE or production readiness.
- Do not depend on private databases, UI automation, undocumented Harness internals, or a Harness patch as evidence of a supported route.
- Keep the MVP to exactly two equal Codex CLI clients and text messages. Do not introduce Master/Subagent, parent/child, group, automatic hand-off, Web3, or cross-Harness semantics.
- Keep evidence claims separate from inference. Use repository-relative locators and record source version, access date, command, exit code, and evidence status.
- Never commit server addresses, credentials, tokens, private keys, cookies, local `.env` files, or unredacted logs.
- Do not claim E2EE, arbitrary existing-TUI attachment, peer-message injection, or `429` observation without the required public evidence and independent review. No implementation may claim E2EE.
- Do not create or modify an R4 security-design decision on behalf of the independent security reviewer; record only the supplied review metadata and disposition.
- A future relay/mailbox adapter requires an explicit ADR and must remain narrow; do not introduce a generic IR.
