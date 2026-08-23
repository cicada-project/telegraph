# Security policy

## Current security status

The product route was approved on 2026-08-23 as a lightweight Rust-first core with the stable SDK companion route in ADR 0003. R1, R4, and ADR 0001/0002/0003 have independent-review dispositions of **accept with conditions**. This repository contains no client, message transport, relay, offline mailbox, pairing implementation, key handling, or runtime security boundary. Only T0/T1 neutral-scaffold work from the reviewed task breakdown is currently authorized; relay, client, crypto/provider, bridge, integration, and deployment work remain blocked pending the next implementation gate and dependency/storage closure.

The project does not implement or verify end-to-end encryption (E2EE), and makes no E2EE claim. Any future security claim must identify its threat model, evidence, and independent reviewer; a product analogy such as “Telegram-like” is not a cryptographic specification.

The long-term identity is owned by a Telegraph client/device or OS-user daemon, not by a Codex thread. A thread is an opaque local endpoint and the server must not receive the real Codex thread ID. One thread may have multiple local or remote peers; each thread-to-thread pair requires an independent channel and ratchet state. These are design constraints from the conditionally accepted R4 design, not runtime guarantees; dependency, storage, provider, and implementation-review conditions remain blockers.

Relay-generated `device_code` and short-lived human `user_code` values remain subject to the open R4 conditions and are only rendezvous inputs. They are not standalone identity or encryption proof. The conditionally accepted design must bind them to long-term identity keys and a pairing transcript, derive a safety code from that transcript, and require both humans to confirm the same safety number or fingerprint before activation.

The future relay boundary, if the R4 conditions are closed, is limited to ciphertext, offline mailbox state, and delivery receipts. Relay deployment is physically independent from this repository; the first deployment host is intentionally not recorded here. No relay exists in the current repository.

Web3 is a deferred direction, not an MVP dependency. Any later narrow relay/mailbox adapter requires an explicit ADR and must not introduce a generic IR.

## Reporting a sensitive issue

Do not put credentials, tokens, private keys, cookies, server addresses, or unredacted logs in a public issue or pull request. The maintainer/security reporting channel is pending organization-owner assignment; until it is published, do not disclose sensitive material in this repository.

## Required future review scope

The R4 review covers pairing, identity verification, device-code binding, human safety-number or fingerprint confirmation, key lifecycle, relay and retention, offline delivery, message ordering, replay protection, key rotation, revocation, and audit privacy. Its conditions remain open. No message-transport, relay, client, crypto/provider, or deployment implementation may be treated as accepted while authorization is limited to the T0/T1 neutral scaffold.
