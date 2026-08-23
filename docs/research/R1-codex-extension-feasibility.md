---
evidence_id: R1-telegraph-codex-route-20260823
gate: R1
claim_ids:
  - R1-C01
  - R1-C02
  - R1-C03
  - R1-C04
  - R1-C05
  - R1-C06
  - R1-C07
classification: public-stable-api
source_type: mixed-primary
source_version_or_commit: "Codex repository/app-server README commit 7b5b3bd5a2418a5e142449c9ab95e057d14bc98a; local codex-cli 0.141.0; npm @openai/codex-sdk 0.149.0; PyPI openai-codex 0.147.0"
accessed_at_utc: "2026-08-23T07:39:55Z"
status: corroborated
reviewer: independent-subagent-r1-review
reviewed_at_utc: "2026-08-23T07:49:09Z"
design_gate: accept_with_conditions
implementation_authorization: blocked
---

# R1 — Codex CLI extension feasibility

> This is a research report, not implementation authorization. It does not establish a minimum supported Codex version, arbitrary TUI attachment, peer-message injection into an existing TUI, `429` observation, or any encryption property.

## Scope and route label

R1 asks whether Telegraph can use a public Codex route to support two equal Codex CLI clients: a companion-owned local thread that can send and receive text, with a user-facing installation and permission flow. The report separates public documented method surfaces from internal details and local observations.

**Route label: `companion path (conditional)`.** The current product contract says “native Messenger plugin”. The recommendation below is conditional on the product owner explicitly deciding that a companion-owned client satisfies that contract. If “native” is mandatory, this report recommends defer until a supported native route is independently established.

## Telegraph MVP boundary

The R1 decision is constrained by the current MVP contract:

- exactly two equal Codex CLI clients;
- text-only messages, pairing, long-term client/device identity, opaque local thread endpoints, delivery/retry semantics, and local audit;
- a future central relay may handle only ciphertext, offline mailbox state, and delivery receipts, with physical deployment independent from this repository;
- no parent/child or Master/Subagent semantics, attachments, files, shared workspaces, command execution, automatic task hand-off, group chat, external chat platforms, DeepSeek/other-Harness compatibility, Web3, or generic cross-Harness IR;
- no implementation, relay, cryptographic, or deployment work before the applicable research and independent-review gates.

## Executive conclusion

The preferred companion route is the stable Python `openai-codex` SDK with its pinned CLI runtime, controlling a companion-owned Codex thread. Where the SDK does not expose a required method, the companion may research the documented Codex App Server JSON-RPC surface over local stdio or a local socket. This is a bounded candidate route, not a final support promise.

The TypeScript SDK is evaluated separately. Its current registry publication is useful evidence for maturity and API shape, but it is not substituted for the Python SDK recommendation or treated as a minimum version.

The direct `codex app-server` command and its documented method surface are research inputs. The CLI labels the overall App Server command experimental; that does not make every documented core method an `experimentalApi` method. WebSocket, Remote Control, and MCP low-level routes are not production support recommendations for Telegraph.

Attaching to an arbitrary already-running TUI session is **unknown/defer**. The available evidence does not establish that any supported surface injects a peer message into an existing TUI as user-visible peer input.

Observation or structured handling of `429`-class events remains unknown. The R1 gate text mentions `Recover`, which appears to be Reflex-specific; it is not evidence for Telegraph.

The independent review by `independent-subagent-r1-review`, recorded at `2026-08-23T07:49:09Z`, has disposition **accept with conditions**. It corroborates the bounded documented method-surface, registry, and local-baseline evidence; it does not establish arbitrary existing-TUI attachment, user-visible peer injection, `429` observation, or any encryption property. The local workstation observations remain C-level experimental evidence only, and this disposition does not authorize implementation.

## Claim and evidence ledger

Every material claim has an evidence ID, an explicit status, and a precise section, metadata field, or fixed Git commit locator.

| Claim | Evidence ID | Exact locator | Status |
|---|---|---|---|
| `companion path (conditional)` can use a companion-owned local thread | R1-C01 | [Codex SDK — TypeScript library](https://developers.openai.com/codex/sdk/#typescript-library), [Codex SDK — Python library](https://developers.openai.com/codex/sdk/#python-library), [App Server — Connect the CLI terminal UI](https://developers.openai.com/codex/app-server/#connect-the-cli-terminal-ui), [Pinned App Server README — Lifecycle Overview](https://github.com/openai/codex/blob/7b5b3bd5a2418a5e142449c9ab95e057d14bc98a/codex-rs/app-server/README.md#lifecycle-overview), [Pinned App Server README — API Overview](https://github.com/openai/codex/blob/7b5b3bd5a2418a5e142449c9ab95e057d14bc98a/codex-rs/app-server/README.md#api-overview) | corroborated |
| Core App Server thread/turn methods and events exist as a documented protocol surface | R1-C02 | [Pinned App Server README — Lifecycle Overview](https://github.com/openai/codex/blob/7b5b3bd5a2418a5e142449c9ab95e057d14bc98a/codex-rs/app-server/README.md#lifecycle-overview), [Pinned App Server README — API Overview](https://github.com/openai/codex/blob/7b5b3bd5a2418a5e142449c9ab95e057d14bc98a/codex-rs/app-server/README.md#api-overview) | corroborated |
| Python SDK is published as stable and pins its CLI runtime | R1-C03 | [PyPI metadata `info.classifiers`, `info.version`, `info.requires_python`, `info.requires_dist`](https://pypi.org/pypi/openai-codex/json), accessed 2026-08-23 | corroborated |
| TypeScript SDK and CLI registry observations are current snapshots, not support floors | R1-C04 | [npm `@openai/codex-sdk` package](https://www.npmjs.com/package/%40openai/codex-sdk), [npm `@openai/codex` package](https://www.npmjs.com/package/%40openai/codex), package version/license sidebar, accessed 2026-08-23 | corroborated |
| Local Codex CLI and runtime baseline | R1-C05 | This report §Minimum reproducible local experiment; exact commands and exit codes below | corroborated |
| `429` observation remains unknown | R1-C06 | Orchestration contract `docs/04-research-gates.md` §R1 — Codex CLI extension feasibility, “Must answer” bullet 2; no accepted Telegraph evidence | unverified |
| Plugin/hooks/skills/MCP do not establish a Telegraph ingress route | R1-C07 | This report §Negative boundaries; local `codex --help`, `codex mcp-server --help`, and official [Codex CLI documentation](https://developers.openai.com/codex/cli/#use-skills-and-plugins) | corroborated |

The independent review corroborates C01–C05 and C07 as bounded evidence. C06 remains `unverified` because it records an unresolved absence of accepted `429` evidence; it does not verify a `429` event.

## Official sources and access date

Access date for the sources in this report: **2026-08-23**. Moving documentation and registries are recorded as observations with access time; they do not define a minimum supported version.

| Source | Exact section or metadata locator | Evidence classification |
|---|---|---|
| [Codex SDK documentation](https://developers.openai.com/codex/sdk/) | `#typescript-library` and `#python-library` | Public documented surface; exact peer-message semantics still require verification. |
| [Codex App Server documentation](https://developers.openai.com/codex/app-server/) | `#connect-the-cli-terminal-ui` | Public documented surface; not proof of arbitrary TUI attachment. |
| [Pinned Codex App Server README](https://github.com/openai/codex/blob/7b5b3bd5a2418a5e142449c9ab95e057d14bc98a/codex-rs/app-server/README.md) | Commit `7b5b3bd5a2418a5e142449c9ab95e057d14bc98a`, sections `Lifecycle Overview` and `API Overview` | Fixed primary source for method/event names. |
| [PyPI `openai-codex` metadata](https://pypi.org/pypi/openai-codex/json) | `info.classifiers`, `info.version`, `info.requires_python`, `info.requires_dist`, `info.license_expression` | Primary registry observation at 2026-08-23. |
| [npm `@openai/codex-sdk`](https://www.npmjs.com/package/%40openai/codex-sdk) | Package README, install requirement, version and license sidebar | Primary registry observation at 2026-08-23. |
| [npm `@openai/codex`](https://www.npmjs.com/package/%40openai/codex) | Package README, version and license sidebar | Primary runtime-package observation at 2026-08-23. |
| [Codex CLI documentation](https://developers.openai.com/codex/cli/) | `#use-skills-and-plugins`, `#compose-with-scripts-and-ci` | Public product documentation; no Telegraph message API claim. |

## Version and separate license observations

Package and runtime licenses are recorded separately. The license of one package is not generalized to an unverified local binary or App Server runtime.

| Component/surface | Version observation | Package license evidence | Runtime license evidence | Interpretation |
|---|---|---|---|---|
| Python `openai-codex` SDK | PyPI `0.147.0` observed 2026-08-23; `requires_python >=3.10`; dependency pins `openai-codex-cli-bin==0.147.0` | PyPI `info.license_expression` reports Apache-2.0 | `openai-codex-cli-bin` runtime license was not independently verified here: **unknown** | Published as `Development Status :: 5 - Production/Stable`; preferred SDK candidate. The version is a registry observation, not a minimum. |
| TypeScript `@openai/codex-sdk` | npm `0.149.0` observed 2026-08-23; Node.js 18+ requirement | npm package sidebar reports Apache-2.0 | Its `@openai/codex` CLI runtime package reports Apache-2.0 on npm; the local binary provenance remains **unknown** | Separate maturity track; not the primary recommendation. The version is a registry observation, not a minimum. |
| Local Codex CLI | `codex-cli 0.141.0` from local `codex --version` | Local binary package provenance/license not independently verified | Local runtime license: **unknown** | C-level experiment baseline only; never infer a support floor from it. |
| Codex App Server command | Bundled with local CLI; `codex app-server --help` exited `0` | Source package and runtime package are not separately resolved for this local binary | **unknown** for this report | The command is labeled experimental overall; core method maturity is assessed separately below. |
| MCP server | Bundled with local CLI; `codex mcp-server --help` exited `0` | Not independently verified for this runtime | **unknown** for this report | Low-level research input, not production Telegraph support. |

## Core App Server method and event surface

At fixed Codex commit `7b5b3bd5a2418a5e142449c9ab95e057d14bc98a`, the App Server README documents the following method surface:

- `thread/start` and `thread/resume` create or reopen a companion-owned thread.
- `turn/start` submits user input and starts a turn.
- `turn/steer` adds input to an already in-flight regular turn.
- `turn/interrupt` requests cancellation of an in-flight turn.
- `thread/inject_items` appends raw Responses API items to a loaded thread's **model-visible history without starting a user turn**.
- Lifecycle notifications include `thread/started`, `turn/started`, `item/started`, `item/completed`, and `turn/completed`.

`thread/inject_items` is not evidence of an existing TUI becoming visible to a peer, and it is not equivalent to a user-visible peer-input channel. It only describes a model-history method surface. The pinned README does not mark the listed core thread/turn methods as requiring `capabilities.experimentalApi`; this method-level observation must be kept separate from the CLI's overall `[experimental]` App Server command label.

The method surface is therefore useful for a companion-owned thread. It does not solve arbitrary existing-TUI attachment, identity binding, pairing, relay, offline delivery, or Telegraph's peer protocol.

## Capability matrix

| Required capability | Evidence on 2026-08-23 | Classification | Decision |
|---|---|---|---|
| Start a companion-owned local Codex thread | Python/TypeScript SDK docs and pinned App Server `thread/start` | Public documented surface | Candidate under `companion path (conditional)`; prefer Python SDK. |
| Resume a companion-owned thread | SDK docs and pinned App Server `thread/resume` | Public documented surface | Candidate; verify identity and lifecycle policy. |
| Start, steer, interrupt turns | Pinned App Server `turn/start`, `turn/steer`, `turn/interrupt` and event sections | Public method surface; command overall experimental | Candidate for companion-owned thread; independently review version policy. |
| Observe `item/completed` and `turn/completed` progress | Pinned App Server lifecycle/event section | Public documented event surface | Candidate for local audit; no peer transport semantics implied. |
| Append model-visible history without a user turn | Pinned App Server `thread/inject_items` in API Overview | Public documented method surface | Candidate only for a companion-owned thread; not TUI-visible peer input. |
| Use stable Python SDK with pinned runtime | PyPI 0.147.0 metadata and `openai-codex-cli-bin==0.147.0` | Primary registry observation | Preferred route, conditional on independent review and product decision. |
| Use TypeScript SDK | npm 0.149.0 observation, Node 18+ | Primary registry observation | Separate maturity track; not preferred route for this gate. |
| Receive a peer message in an arbitrary existing TUI session | No accepted public method or lifecycle evidence establishes this | Unknown | Defer; do not claim support. |
| Observe structured `429` events | No accepted Telegraph evidence | Unknown | Defer; keep separate from Reflex. |
| Use plugin, hooks, or skills as peer ingress | Extension surfaces are documented, but no public peer-message ingress contract was found | Negative boundary | Not a production R1 route. |
| Use MCP as peer ingress | Local help exposes stdio MCP, but no accepted Telegraph ingress contract | Negative boundary | Not production support. |
| Use WebSocket or Remote Control | Remote surfaces exist, but arbitrary TUI and lifecycle semantics are unresolved | Experimental/unknown | Research input only; not production support. |

## Native versus companion product decision

The product contract calls for a native Messenger plugin. R1 can recommend only **`companion path (conditional)`** on the evidence above:

1. If the product owner accepts a companion-owned Codex client as satisfying the MVP boundary, the Python SDK plus pinned runtime is the preferred first experiment, with direct App Server stdio/local socket only where necessary.
2. If “native” means an official native Messenger package with a supported external ingress API, the current evidence does not establish it; the gate remains deferred.
3. Neither decision authorizes transport, pairing, relay, or cryptographic implementation.

## Negative boundaries: plugins, hooks, skills, MCP, and remote control

- The CLI help lists a `plugin` command, and the official CLI documentation discusses plugins/skills, but neither is evidence of a stable peer-message ingress into an arbitrary existing thread.
- Hooks and skills can be research inputs for lifecycle or instruction customization; no accepted public contract makes them a thread-to-thread transport or identity boundary.
- `codex mcp-server` is a stdio MCP server surface. The available evidence does not establish that it provides Telegraph pairing, peer ingress, delivery receipts, or safe existing-TUI attachment; it is not production support.
- WebSocket and Remote Control expose low-level remote surfaces. They are not a production Telegraph route on this evidence and do not remove the need for a product-level peer protocol.

## Minimum reproducible local experiment

The following commands were run read-only on the experiment workstation in the Telegraph repository. No server was started, no sign-in was attempted, and no package was installed.

| Command | Exit code | Key observation |
|---|---:|---|
| `codex --version` | 0 | `codex-cli 0.141.0` |
| `codex --help` | 0 | Lists `plugin`, `mcp-server`, `app-server`, and `remote-control`. |
| `codex app-server --help` | 0 | Lists stdio, Unix-socket, WebSocket, and `off` listen options; labels App Server tooling experimental. |
| `codex mcp-server --help` | 0 | Describes an MCP server using stdio; no Telegraph ingress contract shown. |
| `codex exec --help` | 0 | Describes non-interactive execution, JSONL output, resumption, and sandbox options; no peer-message injection option shown. |
| `node --version` | 0 | `v22.17.1` |
| `npm --version` | 0 | `10.9.2` |
| `py --version` | 0 | `Python 3.12.10` |
| `python --version` | 9009 | Windows shim was not executable; this is not a Python support result. |
| `npm root -g` | 0 | Global npm root resolved; requested SDK package directories were absent locally. |
| Direct and recursive package checks for `@openai/codex-sdk` and `openai-codex` | 0 | Neither requested package was found in the checked global or repository-local paths. |

This is the initial C-level experiment baseline: local CLI `0.141.0`, Python SDK registry observation `0.147.0`, and TypeScript SDK registry observation `0.149.0`. These values are starting points for a reproducible experiment matrix, not a minimum supported version or lower-bound compatibility claim.

## Independent review disposition

**Disposition: accept with conditions.** The independent R1 review finds the technical evidence loop closed for the documented method surface, registry observations, and local baseline. This disposition does not authorize implementation. Arbitrary existing-TUI attachment, user-visible peer injection, `429` observation, and encryption remain unknown. Before any implementation task, the SDK/runtime pin must be fixed and independently reviewed, and the product owner must accept the `companion path (conditional)` route (or choose a native route/defer). R4 is a separate gate with its own independent-review disposition of **accept with conditions**; its open conditions remain implementation blockers.

## Risks and open decisions

1. The word “native” in the Messenger plugin contract is not resolved by the companion route; the product owner must decide whether `companion path (conditional)` is acceptable.
2. Python SDK and TypeScript SDK registry versions are moving observations, not support floors. The Python SDK's pinned runtime must be reviewed as a separate package and license.
3. App Server's core method surface and the overall experimental CLI command have different maturity labels; they must not be conflated.
4. `thread/inject_items` writes model-visible history without starting a user turn, but it is not a TUI-visible peer-input channel.
5. Existing-TUI attachment is unknown and intentionally deferred.
6. Plugins, hooks, skills, MCP, WebSocket, and Remote Control do not establish a production Telegraph ingress route on the current evidence.
7. `429` observation is unknown and appears to belong to the Reflex research question rather than Telegraph.
8. The local workstation did not have the requested SDK packages installed, so package-level behavior was not exercised.
9. The companion route does not decide long-term client/device identity, opaque endpoint binding, per-pair channels/ratchets, pairing, relay, retention, replay, ordering, audit privacy, or end-to-end encryption. Those questions belong to R4 and independent security review.

## Claims explicitly not made

This report does not claim a minimum supported Codex version, a stable public API for arbitrary TUI attachment, peer-message injection into existing TUI sessions, structured `429` observation, or acceptance of WebSocket/Remote Control/MCP low-level routes. It makes no assertion about end-to-end encryption. It does not authorize implementation.
