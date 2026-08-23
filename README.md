# Telegraph

Telegraph is a research-gated Cicada project for direct text conversation between two equal AI threads.

## Current status

The R1 Codex extension-feasibility gate and the R4 Telegraph security-design gate both have an independent-review disposition of **accept with conditions**. Those conditions remain open, so implementation authorization is **blocked**. The current contents are governance and research material only; there is no client, relay, message transport, mailbox, or cryptographic implementation here, and E2EE is neither implemented nor claimed.

The R1 report includes C-level local workstation observations and records its independent-review disposition. It is not a minimum-support claim or implementation authorization.

- [R1 Codex extension feasibility](docs/research/R1-codex-extension-feasibility.md)
- [R4 Telegraph security design](docs/security/R4-telegraph-security-design.md)
- [Evidence and citation convention](docs/evidence/README.md)
- [Security policy](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)

## Product boundary

The long-term Cicada vision is for any two threads in compatible open-source harnesses to communicate as peers. The current Telegraph MVP is narrower: exactly two Codex CLI peers, both acting as clients, with text-only messages, mutually confirmed pairing, identity binding, delivery/retry semantics, and local audit. The MVP acceptance target remains two peers even though the long-term model permits many thread connections.

The future Telegraph repository may contain a client and a central relay server as separate product components, but the relay's physical deployment location is independent of this repository. The first deployment host must not be recorded here. A future relay is intended to process ciphertext, offline mailbox state, and delivery receipts only; it has not been implemented.

The intended identity model, pending R4 validation, is one long-term identity per Telegraph client/device or OS-user daemon—not one identity per thread. A thread is only an opaque local endpoint; the real Codex thread ID stays inside its client. One thread may connect to multiple same-machine or different-machine threads, with an independent channel and ratchet state for every thread-to-thread pair. The server must not see a real Codex thread ID.

The MVP does not include a parent/child or Master/Subagent hierarchy, attachments, files, shared workspaces, command execution, automatic task hand-off, group conversation, external chat platforms, DeepSeek Harness compatibility, Web3 transport, or a broad cross-harness IR. Web3 is a deferred direction only. Any future narrow relay/mailbox adapter requires an explicit ADR; a generic IR remains out of scope.

“Telegram-like” describes a direct-conversation user experience. It does not select a transport or cryptographic protocol. E2EE is not implemented or available from this repository, and no E2EE claim is made.

The relay-generated `device_code` and short-lived human `user_code` are only rendezvous inputs pending R4 validation. Neither is an identity or encryption proof. The two clients must exchange identity keys and a pairing transcript, derive the same safety code, and both humans must confirm the safety number or fingerprint before a channel activates.

## Research gate rule

No implementation task begins until the Telegraph user flow, scope, non-goals, acceptance conditions, supported Codex route, risk analysis, and independent-review plan are frozen. R1 must establish a supported public route; R4 must produce and independently review a threat model and security design before any message transport work. The conditional acceptance of both gates does not authorize implementation; their recorded conditions remain blockers until closed.

Do not put server addresses, credentials, tokens, private keys, cookies, or local `.env` files in this repository.
