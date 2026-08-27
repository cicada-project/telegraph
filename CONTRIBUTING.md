# Contributing to Telegraph

## Current contribution scope

Before the authorized gate is reached, contributions are limited to governance, product-contract clarification, research notes, evidence metadata, and review templates. Do not add client code, relay code, message transport, mailbox implementation, cryptographic code, deployment configuration, or an unreviewed implementation dependency graph.

After a task is authorized by the accepted gate metadata, contributions must still include the implementation checklist from that task and the independent-review disposition. No implementation is allowed to rely on undocumented internal harness behavior, unreviewed capability assumptions, or prior informal claims.

## Research requirements

Every material claim must include an evidence ID and a source that another reviewer can inspect. Reports must separate public stable APIs from internal implementation details, local experiments, and inference. Record the observed version or commit, access date, reproducible read-only command where applicable, and evidence status. Do not assert E2EE, production readiness, or release support until the corresponding gate and independent-review closure is recorded.

Use repository-relative paths in committed evidence. Redact server addresses, credentials, tokens, private keys, cookies, local environment files, and other sensitive values. Do not commit raw logs when a redacted summary and digest are sufficient.

## Pull requests

Each pull request must state its gate and complete the repository pull-request checklist. An independent reviewer is required for gate decisions. A passing documentation PR does not authorize implementation or establish a security guarantee.

Before implementation is considered, the user flow, scope, non-goals, acceptance conditions, risk analysis, supported Codex route, and independent-review plan must be frozen. Every implementation PR must show commit provenance to its gate source and reviewer disposition.

No contributor may bypass a blocked gate (including provider/dependency, T3b state durability, full T0/T4/T5/T6 integration, and deployment readiness) or treat an unclosed gate as production-ready.
