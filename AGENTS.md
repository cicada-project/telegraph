# Telegraph repository instructions

- The product route is approved (2026-08-23) as a lightweight Rust-first core with the stable SDK companion route in ADR 0003. R1, R4, and ADR 0001/0002/0003 have independent-review dispositions of **accept with conditions**; E2EE is not implemented, verified, or claimable.
- Current implementation authority is limited to the reviewed task breakdown's T0/T1 neutral scaffold. Follow that breakdown and its file ownership exactly; T2+ work remains blocked pending the next implementation gate.
- T1 is neutral framing only. Do not freeze the reviewed crypto profile, provider-specific fields, or confirmation semantics in the neutral scaffold.
- Any crypto/provider, client/channel, relay/transport, bridge, or deployment implementation requires the next implementation gate and an independent review; a passing build or vector is not a security claim.
- Do not depend on private databases, UI automation, undocumented Harness internals, or a Harness patch as evidence of a supported route.
- Keep the MVP to exactly two equal Codex CLI clients and text messages. Do not introduce Master/Subagent, parent/child, group, automatic hand-off, Web3, or cross-Harness semantics.
- Keep evidence claims separate from inference. Use repository-relative locators and record source version, access date, command, exit code, and evidence status.
- Never commit server addresses, credentials, tokens, private keys, cookies, local `.env` files, or unredacted logs.
- Do not claim E2EE, arbitrary existing-TUI attachment, peer-message injection, or `429` observation without the required public evidence and independent review. No implementation may claim E2EE.
- Do not create or modify an R4 security-design decision on behalf of the independent security reviewer; record only the supplied review metadata and disposition.
- A future relay/mailbox adapter requires an explicit ADR and must remain narrow; do not introduce a generic IR.
