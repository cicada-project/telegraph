# T7 Remote Environment Preflight — 2026-08-27

## Disposition

**BLOCKED — remote validation and deployment preflight.**

This record documents a read-only preflight of the two intended validation
hosts. The repository inputs are present and identical on both hosts, but the
Rust toolchain and the managed standalone Codex installation required for the
planned two-host run are not available. The observed outbound download
behavior is an environment readiness issue; it is not a security finding and
does not imply a network vulnerability.

The following gates remain blocked until the conditions in [Unlock conditions](#unlock-conditions)
are rechecked successfully:

- C1 provider/dependency graph enforcement;
- T0 root/workspace integration and its authoritative lockfile checks;
- the two-host Telegraph run;
- Codex CLI bridge acceptance;
- deployment and final end-to-end acceptance.

No end-to-end encryption (E2EE) claim is made. This preflight does not verify
cryptographic integration, session bridging, relay behavior, or the written
threat-model vectors.

## Scope and provenance

- Preflight date: `2026-08-27` (Asia/Shanghai).
- Hosts were accessed only through the authorized SSH path and repository Git
  operations. No source or configuration was copied with `scp`.
- No WSL was used. No local build or local test was run for this preflight.
- The exact checked-out validation branch was
  `codex/remote-validation-t0-20260827`.
- Both hosts reported the same clean clone at commit
  `94905052306382ad14d1a3491757e234ae580fb3`.
- Both hosts reported the same repository lockfile SHA-256, recorded as
  `ca4f...319b` in the operator evidence. The abbreviated form is retained
  here so this document does not invent or silently alter the recorded value.
- Repository integrity checks on both hosts reported clean `git fsck`.

The preflight was limited to host readiness, repository identity, and
connectivity needed to install the pinned toolchain and managed Codex client.
It did not modify either host.

## Host inventory

| Role | Address | Hostname | OS | CPU / memory | Swap | Git |
| --- | --- | --- | --- | --- | --- | --- |
| A | `121.89.91.198` | `iZ0jler49wa1igja6sg6wsZ` | Ubuntu 22.04.5 | 2 vCPU / 1.6 GiB | none | `2.34.1` |
| B | `8.146.226.49` | `iZ0jl62b2yas1jk9vp7kknZ` | Ubuntu 22.04.5 | 2 vCPU / 1.6 GiB | none | `2.34.1` |

The two hosts are otherwise treated as separate peers for the eventual
acceptance run. Physical co-location of a client and relay is not a product
requirement; this document only records the selected validation placement.

## Detection matrix

| Detection | Host A (`121.89.91.198`) | Host B (`8.146.226.49`) | Result / impact |
| --- | --- | --- | --- |
| OS and resource inventory | Ubuntu 22.04.5; 2 vCPU; 1.6 GiB; no swap | Ubuntu 22.04.5; 2 vCPU; 1.6 GiB; no swap | PASS for inventory; resource limits remain a deployment risk to assess after toolchain readiness |
| Git client | `2.34.1` | `2.34.1` | PASS |
| Clone branch | `codex/remote-validation-t0-20260827` | `codex/remote-validation-t0-20260827` | PASS |
| Working tree | clean | clean | PASS |
| Commit identity | `94905052306382ad14d1a3491757e234ae580fb3` | `94905052306382ad14d1a3491757e234ae580fb3` | PASS; inputs match |
| Repository lockfile SHA | `ca4f...319b` | `ca4f...319b` | PASS; recorded values match |
| Git object integrity | `git fsck` clean | `git fsck` clean | PASS |
| `rustc` | not installed | not installed | BLOCKED; no pinned compiler |
| `cargo` | not installed | not installed | BLOCKED; no build/test runner |
| `rustup` | not installed | not installed | BLOCKED; no reproducible Rust toolchain manager |
| APT Rust availability | only `1.75` available | only `1.75` available | BLOCKED; below the project-pinned Rust `1.85.1` requirement |
| `sh.rustup.rs` reachability | IPv4 endpoint reachable, but second-stage `rustup-init` download was extremely slow: `674808/20838840` bytes after 60 seconds | bootstrap script reached, but second-stage download failed | BLOCKED; Rust `1.85.1` cannot be installed reproducibly yet |
| Official managed Codex installer | `chatgpt.com/codex/install.sh` timed out; resolved endpoint was observed but is intentionally not recorded here | timed out when forcing IPv4 | BLOCKED; managed standalone Codex binary is absent |
| Codex managed standalone layout | absent | absent | BLOCKED; no supported managed Codex executable for CLI acceptance |
| Two-host Telegraph execution | not attempted | not attempted | BLOCKED by missing toolchain and client runtime |

The network observations above intentionally omit private routes, proxy values,
credentials, and other sensitive connection details. They should be repeated
after any connectivity change rather than treated as durable service-level
measurements.

## Gate interpretation

### C1 provider/dependency gate

C1 cannot be closed on the hosts because neither host has the pinned Rust/Cargo
toolchain needed to resolve, lock, and verify the unified dependency graph.
The remote preflight therefore supplies no C1 pass evidence. The local C1
checker and dependency evidence must be rerun from the exact committed source
after the remote Rust `1.85.1` installation is available.

### T0 integration gate

T0 remains blocked. A clean, matching Git clone proves source identity only; it
does not prove that the workspace compiles, tests, lints, or passes the
provider-policy checks on either target host. No local build was substituted
for this missing remote evidence.

### Two-host and Codex CLI acceptance

The two-host acceptance vector has not started. In particular, there is no
evidence yet for secure pairing, peer identity confirmation, encrypted message
delivery, receipt/audit correspondence, rejection of replay or invalid
identity, or Codex session input/output bridging.

The managed standalone Codex layout is a prerequisite for the planned CLI
acceptance. Its absence is recorded as a hard readiness blocker, not worked
around with an unverified package layout.

### Deployment

Deployment is blocked. No service was installed, started, upgraded, or exposed
on either host during this preflight. The selected future placement may use
host A for the relay and one client and host B for the second client, but that
placement is not an execution record and is not a claim that the relay is
ready.

## Unlock conditions

The following conditions are required before resuming remote validation:

1. Restore stable outbound TCP 443 and DNS resolution, without recording or
   disclosing private routing or proxy material, for the official sources used
   by the toolchain and managed Codex installer: `sh.rustup.rs`,
   `static.rust-lang.org`, and `chatgpt.com`.
2. Install and verify the project-pinned official Rust toolchain `1.85.1` on
   each host. The installation must complete its second-stage download; an
   APT-only `1.75` compiler is not an acceptable substitute.
3. Install and verify the official managed standalone Codex distribution on
   each host. Confirm the managed executable is present at the installer-owned
   location expected by the installed Codex release. Record only version and
   path-presence evidence; do not expose credentials or tokens.
4. From each host, use Git to fetch and check out the exact validation commit
   `94905052306382ad14d1a3491757e234ae580fb3`, verify a clean worktree, and
   recheck the authoritative lockfile SHA.
5. Rerun the full remote preflight independently on A and B, then run the
   acceptance sequence serially: server readiness, client A, client B, secure
   pairing and identity confirmation, unique-ID plaintext test payload,
   encrypted relay delivery, peer session input/reply, and local audit checks.
6. Collect a separate independent security review against the written threat
   model before making any E2EE claim. Relay opacity must be demonstrated by
   evidence; it must not be inferred from TLS, a device code, or a successful
   functional test.

## Reproducibility and evidence boundary

The next operator should attach the fresh command outputs and timestamps to a
successor record, including:

- `rustc --version --verbose`, `cargo --version`, and the managed Codex version;
- the exact Git commit, clean status, lockfile digest, and `git fsck` result on
  both hosts;
- the C1/T0 check results produced on the remote hosts;
- the two-host test transcript and audit-event identifiers; and
- the independent security-review disposition.

Until those outputs exist, this document is a **BLOCKED preflight record** and
not a release, deployment, or E2EE attestation.

## Change-safety record

- Files changed by this task: this new evidence document only.
- Source, configuration, lockfiles, server state, and client state: not
  modified.
- Transfer method: SSH plus Git operations only; no `scp`.
- Local execution: no build or test; no WSL.
- Validation performed after writing: `git diff --check` on this document.
