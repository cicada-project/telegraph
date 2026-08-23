# Telegraph repository instructions

- Treat this repository as research-only until the R1 Codex extension-feasibility gate and the R4 Telegraph security-design gate are accepted.
- Do not create implementation code, `src/`, `tests/`, relay or transport code, cryptographic code, or deployment configuration during the research phase.
- Do not depend on private databases, UI automation, undocumented Harness internals, or a Harness patch as evidence of a supported route.
- Keep the MVP to exactly two equal Codex CLI clients and text messages. Do not introduce Master/Subagent, parent/child, group, automatic hand-off, Web3, or cross-Harness semantics.
- Keep evidence claims separate from inference. Use repository-relative locators and record source version, access date, command, exit code, and evidence status.
- Never commit server addresses, credentials, tokens, private keys, cookies, local `.env` files, or unredacted logs.
- Do not claim E2EE, arbitrary existing-TUI attachment, peer-message injection, or `429` observation without the required public evidence and independent review.
- Do not create or modify an R4 security-design decision on behalf of the independent security reviewer.
- A future relay/mailbox adapter requires an explicit ADR and must remain narrow; do not introduce a generic IR.
