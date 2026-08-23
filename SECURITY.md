# Security policy

## Current security status

Telegraph is research-only. This repository contains no client, message transport, relay, offline mailbox, pairing implementation, key handling, or runtime security boundary. The R4 security-design gate has an independent-review disposition of **accept with conditions**. Its conditions remain open, so implementation authorization remains **blocked/reject**.

The project does not claim or implement end-to-end encryption (E2EE). Any future security claim must identify its threat model, evidence, and independent reviewer; a product analogy such as “Telegram-like” is not a cryptographic specification.

The long-term identity is owned by a Telegraph client/device or OS-user daemon, not by a Codex thread. A thread is an opaque local endpoint and the server must not receive the real Codex thread ID. One thread may have multiple local or remote peers; each thread-to-thread pair requires an independent channel and ratchet state. These are design constraints from the conditionally accepted R4 design, not runtime guarantees; the open R4 conditions remain implementation blockers.

Relay-generated `device_code` and short-lived human `user_code` values remain subject to the open R4 conditions and are only rendezvous inputs. They are not standalone identity or encryption proof. The conditionally accepted design must bind them to long-term identity keys and a pairing transcript, derive a safety code from that transcript, and require both humans to confirm the same safety number or fingerprint before activation.

The future relay boundary, if the R4 conditions are closed, is limited to ciphertext, offline mailbox state, and delivery receipts. Relay deployment is physically independent from this repository; the first deployment host is intentionally not recorded here. No relay exists in the current repository.

Web3 is a deferred direction, not an MVP dependency. Any later narrow relay/mailbox adapter requires an explicit ADR and must not introduce a generic IR.

## Reporting a sensitive issue

Do not put credentials, tokens, private keys, cookies, server addresses, or unredacted logs in a public issue or pull request. The maintainer/security reporting channel is pending organization-owner assignment; until it is published, do not disclose sensitive material in this repository.

## Required future review scope

The R4 review covers pairing, identity verification, device-code binding, human safety-number or fingerprint confirmation, key lifecycle, relay and retention, offline delivery, message ordering, replay protection, key rotation, revocation, and audit privacy. Its conditions remain open. No message-transport or relay implementation may be treated as accepted while implementation authorization remains **blocked/reject**.
