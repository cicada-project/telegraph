# Evidence and citation convention

Research documents use repository-relative paths and stable source locators. They must distinguish a public stable API from an internal implementation detail, a local experiment, an independent review, and an inference.

## Metadata

Use this YAML front matter for every committed evidence item or report claim:

```yaml
evidence_id: R1-codex-message-injection-001
gate: R1
claim_ids:
  - R1-C03
classification: public-stable-api
source_type: official-doc
source_locator: "https://developers.openai.com/codex/app-server/#api-overview"
source_version_or_commit: "fixed Git commit or registry version"
accessed_at_utc: "2026-08-23T07:39:55Z"
observed_environment: "codex-cli 0.141.0; node 22.17.1"
reproduction:
  command: "codex app-server --help"
  exit_code: 0
  result_summary: "help output observed; no server started"
artifact_sha256: null
status: pending-review
reviewer: null
reviewed_at_utc: null
```

Allowed `source_type` values include `official-doc`, `official-registry`, `git-fixed`, `local-command`, `orchestrator-contract`, and `mixed-primary`.

Allowed `classification` values are:

- `public-stable-api`
- `internal-implementation-detail`
- `local-experiment`
- `independent-review`
- `inference`
- `unverified`

Allowed `status` values are `pending-review`, `unverified`, `corroborated`, and `rejected`. A local observation is not a minimum-support claim. A research report is not implementation authorization.

## Citation rules

- Official documentation citations include the direct URL, exact section or heading, access date, and stated version policy when available. A homepage-only link is insufficient for a material claim.
- Source citations include repository URL, fixed commit, repository-relative path, and line or symbol locator. For a protocol claim, pin a Git commit rather than citing a moving `main` branch.
- Official registry citations include the package URL, exact metadata fields or page section, observed version, and access timestamp. Registry observations are not minimum-support claims.
- Local commands include the exact read-only command, exit code, relevant version, and a short result summary. Do not include machine-specific absolute paths when a repository-relative or normalized locator is sufficient.
- Independent reviews identify the reviewer, review date, scope, disposition, and unresolved risks.
- Inference must be labeled and must not be written as an API guarantee.
- Keep raw sensitive output out of Git. Redact credentials, tokens, private keys, cookies, server addresses, and local environment files; submit only a redacted summary and optional digest.
