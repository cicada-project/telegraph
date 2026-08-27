# Telegraph

Telegraph is a research-gated Cicada project for direct text conversation between two equal AI threads.

## Current status

The product route was approved on 2026-08-23 as a lightweight Rust-first core with the stable SDK companion route described by ADR 0003. R1 and R4, plus ADR 0001/0002/0003, have independent-review dispositions of **accept with conditions**. A subsequent implementation addendum, independently reviewed as **authorize with conditions** by `telegraph-t2-t3-implementation-gate-reviewer-01` at `2026-08-23T13:00:24Z` for source commit `ca37d28bed9a50b776b2f8f2d3396df771207186`, extends permission to T0 handoff glue and owned T2/T3 files without rewriting ADR 0001-0004 or R4's design-review history. R4's gate-local `t0_t1_neutral_scaffold_only` authorization remains historical; T4/T5/T6+ work, including CLI, bridge, integration, release, and deployment, remains blocked. The current checkout now includes planning/evidence and selected owned-implementation artifacts under conditionally scoped review; it is not production-complete. E2EE is neither implemented nor verified, the 30 R4 vectors have not been executed, and no E2EE or production claim is made.

The R1 report includes C-level local workstation observations and records its independent-review disposition. It is not a minimum-support claim or implementation authorization.

- [R1 Codex extension feasibility](docs/research/R1-codex-extension-feasibility.md)
- [R4 Telegraph security design](docs/security/R4-telegraph-security-design.md)
- [T2/T3 implementation-gate evidence](docs/evidence/T2-T3-implementation-gate.md)
- [Evidence and citation convention](docs/evidence/README.md)
- [Security policy](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)

## Product boundary

The long-term Cicada vision is for any two threads in compatible open-source harnesses to communicate as peers. The current Telegraph MVP is narrower: exactly two Codex CLI peers, both acting as clients, with text-only messages, mutually confirmed pairing, identity binding, delivery/retry semantics, and local audit. The MVP acceptance target remains two peers even though the long-term model permits many thread connections.

The future Telegraph repository may contain a client and a central relay server as separate product components, but the relay's physical deployment location is independent of this repository. The first deployment host must not be recorded here. The relay is intended to process ciphertext and opaque mailbox/state metadata only; it has no role in local plaintext, key ownership, or session state.

The intended identity model in the conditionally accepted R4 design is one long-term identity per Telegraph client/device or OS-user daemon—not one identity per thread. A thread is only an opaque local endpoint; the real Codex thread ID stays inside its client. One thread may connect to multiple same-machine or different-machine threads, with an independent channel and ratchet state for every thread-to-thread pair. The server must not see a real Codex thread ID.

The MVP does not include a parent/child or Master/Subagent hierarchy, attachments, files, shared workspaces, automatic task hand-off, group conversation, external chat platforms, DeepSeek Harness compatibility, Web3 transport, or a broad cross-harness IR. Telegraph provides no caller-controlled command, file, or tool operation. The stable SDK may transitively use its matching bundled stdio runtime, and Codex may use tools according to the local endpoint policy; that local behavior is outside Telegraph's caller-controlled interface. Web3 is a deferred direction only. Any future narrow relay/mailbox adapter requires an explicit ADR; a generic IR remains out of scope.

“Telegram-like” describes a direct-conversation user experience. It does not select a transport or cryptographic protocol. E2EE is not implemented or verified in this repository, and no E2EE claim is made.

The relay-generated `device_code` and short-lived human `user_code` are only short-lived rendezvous inputs under the conditionally accepted R4 design. Neither is an identity or encryption proof. The two clients must exchange identity keys and a pairing transcript, derive the same safety code, and both humans must confirm the safety code through an approved out-of-band method before a channel activates.

## Implementation gate rule

The product route, scope, non-goals, acceptance conditions, supported Codex route, risk analysis, and independent-review plan are frozen for the approved planning route. The subsequent implementation addendum permits T0 integration-owner handoff changes to root membership/lock/glue and only owned T2/T3 files; it extends implementation/test permission without changing ADR 0001-0004 or R4's historical `t0_t1_neutral_scaffold_only` field. T3b, dependency/license, and full-system deployment/release evidence remain open; these gates are not yet closed. Every implementation result requires independent review and the accepted task flow; the 30 R4 vectors remain unexecuted, and no task may claim E2EE or production readiness.

Do not put server addresses, credentials, tokens, private keys, cookies, or local `.env` files in this repository.
