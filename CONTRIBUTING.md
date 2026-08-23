# Contributing to Telegraph

## Current contribution scope

Until the R1 and R4 gates are accepted, contributions are limited to governance, product-contract clarification, read-only research reports, citations, evidence metadata, and review templates. Do not add client code, relay code, message transport, mailbox implementation, cryptographic code, deployment configuration, or an implementation dependency graph.

## Research requirements

Every material claim must include an evidence ID and a source that another reviewer can inspect. Reports must separate public stable APIs from internal implementation details, local experiments, and inference. Record the observed version or commit, access date, reproducible read-only command where applicable, and evidence status.

Use repository-relative paths in committed evidence. Redact server addresses, credentials, tokens, private keys, cookies, local environment files, and other sensitive values. Do not commit raw logs when a redacted summary and digest are sufficient.

## Pull requests

Each pull request must state its gate and complete the repository pull-request checklist. An independent reviewer is required for gate decisions. A passing documentation PR does not authorize implementation or establish a security guarantee.

Before implementation is considered, the user flow, scope, non-goals, acceptance conditions, risk analysis, supported Codex route, and independent-review plan must be frozen. No contributor may infer authorization from an internal or undocumented Harness capability.
