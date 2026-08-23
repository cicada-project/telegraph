---
evidence_id: ADR0003-codex-bridge-20260823
gate: ADR0003
classification: independent-review
source_type: mixed-primary
source_locator: "docs/adr/0003-codex-bridge.md"
source_version_or_commit: "Telegraph planning ADR; review metadata recorded below"
accessed_at_utc: "2026-08-23T10:48:55.2592158Z"
reproduction:
  command: "read-only Codex bridge ADR review"
  exit_code: null
  result_summary: "Stable SDK companion design accepted with conditions; implementation remains gated"
artifact_sha256: null
status: corroborated
reviewer: independent-subagent-codex-bridge-adr-review
reviewed_at_utc: "2026-08-23T10:48:55.2592158Z"
design_gate: accept_with_conditions
implementation_authorization: t0_t1_neutral_scaffold_only
security_claim: E2EE_not_claimed
---

# ADR 0003: Rust client with a local Python Codex bridge

- Status: Accepted for design; implementation remains gated
- Date: 2026-08-23
- Decision owner: Telegraph technical lead
- Scope: the companion-owned Codex endpoint of the two-peer, text-only MVP
- Independent review: design accepted with conditions by
  `independent-subagent-codex-bridge-adr-review` at
  `2026-08-23T10:48:55.2592158Z`; implementation remains gated
- Security status: design only; E2EE is not implemented or claimed

## Decision

Telegraph keeps the client and daemon Rust-first. A small, long-lived Python
bridge is the only Codex SDK adapter in the first implementation design. The
Rust side supervises the bridge and speaks a deliberately narrow, versioned
JSON Lines protocol over the bridge process's stdin/stdout. The bridge uses the
published, stable `openai-codex` Python SDK to start or resume a
**companion-owned** local Codex thread and to run turns on it.

The bridge is local-only. It opens no TCP, Unix-socket, WebSocket, MCP, or
remote-control listener. It does not invoke the experimental `codex app-server`
CLI directly. It does not attach to, inject into, or claim control of an
arbitrary existing Codex terminal UI. `attach` means resume a thread previously
created by this bridge and recorded in its own local endpoint store.

This decision records the route selected for future implementation planning. It
does not claim that a bridge, client, relay, thread integration, or E2EE exists,
and it does not close the R1/R4 conditions or authorize implementation. The
product owner approved the Rust-first route on 2026-08-23; that approval is not
an implementation claim.

## Context and constraints

The product contract is exactly two equal Codex CLI peers exchanging text.
Incoming peer text is intended to become conversation input to the local
companion-owned endpoint and the local Codex reply is returned as text. The
MVP has no parent/child or Master/Subagent semantics, attachments, files,
shared workspaces, automatic hand-off, group chat, external chat, Web3, or
generic cross-harness IR, and Telegraph exposes no caller-controlled command,
file-transfer, or tool-control operation. That interface non-goal does not
promise that Codex will never use a locally permitted command or tool after it
receives peer text; the local-owner policy and acceptance requirements below
make that distinction explicit. The device identity, relay, mailbox, pairing,
and privacy rules remain those in R4 and ADR 0001.

R1 labels the supported candidate `companion path (conditional)`. It accepts a
companion-owned local thread as a bounded route but explicitly defers arbitrary
existing-TUI attachment and peer-message injection. This ADR preserves that
boundary. A future product decision that requires a native in-process Messenger
plugin or an existing-TUI ingress must reopen this ADR and R1; it cannot be
implemented by widening this bridge protocol.

Rust remains the owner of Telegraph protocol state, identity/channel policy,
delivery and receipt semantics, local audit, retry rules, and process
supervision. Python is an adapter boundary only. A later official Rust SDK can
replace the bridge behind the trait described below without changing the
Telegraph peer protocol.

## Evidence: what the official sources establish

The sources below are current OpenAI primary sources accessed on 2026-08-23.
Moving documentation and the repository `main` branch are evidence of the
documented public surface, not a support-floor declaration.

| Official source | What it establishes for this ADR |
|---|---|
| [Codex SDK documentation](https://developers.openai.com/codex/sdk/) | The SDK controls local Codex agents; the Python library requires Python 3.10 or later, controls the local Codex app-server over JSON-RPC, publishes stable releases, and includes a pinned Codex CLI runtime dependency. It documents `thread_start`, `thread_resume`, `AsyncCodex`, `Thread.run`, `TurnResult.final_response`, `cwd`, and sandbox presets. The SDK may transitively launch its matching bundled stdio runtime and may use the runtime's capability negotiation; those are implementation details, not a Telegraph direct dependency or support promise. |
| [Official Python SDK README](https://github.com/openai/codex/blob/main/sdk/python/README.md) | The published `openai-codex` package starts local threads and returns a `TurnResult` with a final response; the SDK is Apache-2.0 under the Codex repository. |
| [Official Python SDK API reference](https://github.com/openai/codex/blob/main/sdk/python/docs/api-reference.md) | The public types include `AsyncCodex`, `AsyncThread`, `AsyncTurnHandle`, `ApprovalMode`, `Sandbox`, `thread_start`, `thread_resume`, `thread.turn`, `TurnHandle.run`, `TurnHandle.stream`, `TurnHandle.interrupt`, and `TurnResult.final_response`. It documents the public input types and the published Python requirement. |
| [Official Python SDK FAQ](https://github.com/openai/codex/blob/main/sdk/python/docs/faq.md) | Stable builds track and install the matching runtime; `run()` waits for `turn/completed`; `stream()` supports custom timeout logic; `AsyncCodex` has explicit startup/shutdown; overload retry is separate from blind retry. |
| [Official Codex App Server documentation](https://developers.openai.com/codex/app-server/) | App Server has a JSON-RPC/JSONL stdio surface and documented thread/turn lifecycle. The same page labels the app-server command and WebSocket transport experimental and unsupported for production workloads. Telegraph therefore uses the stable SDK public surface and does not directly depend on those experimental transports. |
| [Official Codex CLI documentation](https://developers.openai.com/codex/cli/) | Codex is a local terminal workflow with explicit permissions and sandbox controls. This supports a local configuration policy, but it does not document a Telegraph peer-ingress API. |
| [Official OpenAI Codex repository](https://github.com/openai/codex) | The upstream Codex project is open source and publishes the SDK/runtime source and release artifacts. A moving repository is not by itself a minimum supported version. |

These sources do **not** establish any of the following: arbitrary existing-TUI
attachment; user-visible peer-message injection into an existing TUI; a
Telegraph pairing or relay protocol; endpoint identity binding; thread-ID
privacy; at-most-once handoff across a process crash; the performance budget
below; E2EE or any cryptographic property; a future official Rust SDK; or a
minimum supported Codex CLI version. They also do not prove that every Codex
internal tool can be disabled by a single public setting. Those are Telegraph
design requirements or open validation work, not OpenAI support claims.

In particular, the App Server page's remote terminal UI example proves that a
documented remote UI mode exists, not that Telegraph may inject a peer message
into an arbitrary user-owned TUI. This ADR makes no such claim.

The R1 question of observing or structuring `429`-class events remains
**unknown**. This bridge is not a Reflex event observer and does not close that
R1 finding.

## Architecture and ownership

```text
Telegraph Rust client/daemon
  - pairing/channel/relay protocol and local audit
  - opaque endpoint handle and message id
  - bridge supervisor and bounded queues
  - CodexEndpoint trait
             |
             | restricted JSONL stdin/stdout, local process only
             v
long-lived Python bridge (one OS user/daemon)
  - stable openai-codex public API only
  - endpoint -> local thread mapping
  - AsyncCodex lifecycle and one turn queue per endpoint
  - local sandbox/cwd policy
             |
             | SDK-owned local transport; no bridge-level app-server CLI
             v
companion-owned local Codex thread
```

The bridge may see plaintext because it is the local endpoint handoff. The
Telegraph relay and Telegraph network transport must never see that plaintext.
The bridge must not put plaintext, credentials, local paths, workspace names,
thread IDs, tool arguments, or file content on Telegraph relay wire. The local
Python SDK/app-server and the normal Codex upstream service may handle the
endpoint plaintext required to run a turn; those local/upstream processing
paths are outside Telegraph's relay E2EE guarantee and are not hidden by this
ADR.

"Local-only" describes the bridge's own listener and control boundary. The
official Codex runtime may still make its normal upstream service connection
when a turn runs; this ADR does not promise offline Codex operation or make a
data-retention claim about that upstream service.

The real Codex thread ID is created/consumed by the local SDK/app-server inside
the bridge boundary. It is not accepted in the bridge request, emitted in a
bridge response, written to the Telegraph audit stream, or sent on Telegraph
relay wire. The bridge's private local mapping may persist it as an
implementation detail needed for resume; that local storage is not a
Telegraph wire field. Likewise, a validated local cwd may be passed to the
local SDK, but neither cwd nor workspace identity is sent on relay wire.

## Bridge lifecycle

### Process and SDK lifecycle

1. Rust starts one bridge child with inherited standard input/output pipes and
   a separately captured stderr. The child is launched with a fixed executable
   and a locked virtual environment; no shell command is constructed from
   peer text.
2. The bridge starts in `starting`, creates one `AsyncCodex` context, and
   answers `health` only after the SDK has initialized. Login is not part of the
   bridge protocol. Authentication is an existing local Codex session or a
   separately reviewed local setup flow; API keys and login codes never cross
   JSONL.
3. Rust sends `start` or `attach` for each endpoint. A start creates a new
   companion-owned thread. An attach resumes only the bridge's local mapping.
   The bridge rejects an endpoint with no local mapping instead of accepting a
   caller-supplied thread ID.
4. The bridge stays resident for multiple peer turns. Rust supervises EOF,
   non-zero exit, protocol violations, and missed health deadlines. The bridge
   never daemonizes away from the supervisor.
5. `shutdown` changes the process to `draining`; no new peer text is accepted.
   A bounded drain completes queued work, interrupts active work at the drain
   deadline, closes `AsyncCodex`, and exits. `shutdown(mode=now)` interrupts
   active work and exits without replaying it.
6. On normal EOF or crash, Rust marks active work as uncertain, closes the
   local pipe, and restarts with bounded exponential backoff. It must not
   blindly replay an uncertain peer message. After restart, endpoints are
   re-attached using the bridge's local endpoint store. A missing or corrupted
   mapping fails closed and requires local repair; it is never guessed from a
   TUI or a database.

The bridge state machine is `starting -> ready -> draining -> stopped`; a
process failure may enter `crashed` before supervision starts a new instance.
An endpoint is `unbound -> starting -> attached -> busy -> attached`, with
`draining`, `failed`, and `unknown` terminal states requiring explicit local
repair or a new endpoint. No state transition is inferred from a pipe timeout.

The stable Python SDK is allowed to launch its published, matching bundled
stdio app-server transitively and to negotiate whatever capability flags that
SDK release requires, including a possible `experimentalApi` capability. The
bridge does not invoke the app-server CLI, construct its JSON-RPC messages, or
select WebSocket/Remote Control transports. Telegraph's support commitment is
therefore the exact stable SDK plus pinned runtime tuple and its tested public
API behavior, not any private or experimental app-server method or capability.

### Endpoint start and attach

`start(endpoint)` performs the equivalent of the documented Python SDK
`thread_start(...)` using the endpoint's local policy and stores the returned
thread ID only in bridge-local state. Repeating the same start is idempotent:
it returns the already attached endpoint and does not create a second thread.

`attach(endpoint)` performs `thread_resume(local_thread_id, ...)` using the
stored local binding. It verifies that the endpoint's stored local policy is
still allowed. Repeating attach is idempotent. `attach` is not an import
operation, does not accept a Codex thread ID, and does not attach to a running
TUI.

There is one ordered queue per local endpoint and one active turn per endpoint.
This deliberately chooses predictable peer-turn ordering over concurrent turns
on the same conversation. A future implementation may have several endpoint
queues in one bridge process, but it must not merge their thread or idempotency
state.

## Restricted JSON Lines protocol

This is a local control protocol, not a generic cross-harness IR. Each line is
one UTF-8 JSON object followed by `\n`; no JSON-RPC, WebSocket, MCP, binary
attachment, or nested tool protocol is accepted. Version `1` rejects unknown
required fields, malformed JSON, duplicate object keys, invalid UTF-8, and
lines larger than 128 KiB before dispatch.

The protocol's only content fields are a bounded UTF-8 plain-text `text` and a
local opaque `endpoint`. `request_id` and `message_id` are local opaque
correlation/idempotency values, not peer identity and not Codex IDs. Control
fields (`v`, `op`, bounded deadlines, status, and error codes) carry no user
content. No real thread ID, path, workspace name, credential, ciphertext,
file, image, command, or tool request is a legal field.

Common request fields:

```json
{"v":1,"request_id":"rq_opaque","op":"..."}
```

`request_id` is unique within the bridge lifetime and is echoed exactly once
by a terminal response. A caller reconnecting after a crash must use a new
request ID; `message_id` provides peer-message idempotency.

### Requests

Start a new companion-owned endpoint:

```json
{"v":1,"request_id":"rq_1","op":"start","endpoint":"ep_opaque"}
```

Resume a previously bridge-owned endpoint:

```json
{"v":1,"request_id":"rq_2","op":"attach","endpoint":"ep_opaque"}
```

Submit one peer message as one new Codex user turn:

```json
{"v":1,"request_id":"rq_3","op":"peer_text","endpoint":"ep_opaque","message_id":"msg_opaque","text":"Plain text from the peer"}
```

The implementation may accept an optional bounded `deadline_ms` on
`peer_text`; it is a local monotonic deadline and is not forwarded to Codex as
prompt text. The bridge rejects empty text, over-limit text, non-string text,
and any image/file/skill/mention input. A peer message is never interpreted as
a command to the bridge.

Cancel a queued or active request:

```json
{"v":1,"request_id":"rq_4","op":"cancel","target_request_id":"rq_3"}
```

Read local process health:

```json
{"v":1,"request_id":"rq_5","op":"health"}
```

Drain and stop:

```json
{"v":1,"request_id":"rq_6","op":"shutdown","mode":"drain"}
```

`mode` is `drain` or `now`; the bridge rejects unbounded or caller-selected
shutdown timeouts. The configured drain deadline is local policy.

### Responses

Successful endpoint lifecycle response:

```json
{"v":1,"request_id":"rq_1","op":"response","kind":"endpoint","endpoint":"ep_opaque","status":"attached"}
```

Successful peer response. `text` is the final assistant response only:

```json
{"v":1,"request_id":"rq_3","op":"response","kind":"peer_text","endpoint":"ep_opaque","message_id":"msg_opaque","status":"completed","text":"Plain final response"}
```

The bridge obtains this text from the SDK `TurnResult.final_response` after
the turn reaches its terminal completion. If the turn completes without a
final response, it returns `no_final_response`; it does not guess by scraping
logs or expose raw items.

Health response:

```json
{"v":1,"request_id":"rq_5","op":"health","status":"ready","active":0,"queued":0}
```

Health is local process state only. It must not include thread IDs, paths,
prompt text, reply text, credentials, or full exception strings.

Every rejected or failed request has this shape:

```json
{"v":1,"request_id":"rq_3","op":"error","code":"backpressure","retryable":true}
```

Error `code` is from a closed, documented set. `detail` is optional, bounded,
and redacted; it is never a Python traceback or model/tool output. A shutdown
acknowledgement is a normal response with `kind":"shutdown"`; the process
then closes its pipes.

### Codex turn semantics

For every accepted `peer_text`, the bridge calls the public Python SDK turn
API with the supplied plain string on the endpoint's companion-owned thread.
It uses `AsyncThread.turn(text)` followed by the returned
`AsyncTurnHandle.run()` (or the equivalent public `AsyncThread.run(text)` when
no cancellation deadline is needed). It never uses `turn/steer`: each peer
message is a new Codex user turn, not appended to an in-flight turn.

The bridge waits for the SDK's terminal turn result. It returns only
`TurnResult.final_response` as the `response.text` field. Intermediate deltas,
reasoning items, command output, file changes, tool calls, token usage, and
the local Codex thread ID stay inside the bridge and are not part of this
protocol. A `final_response` of `None` is an error, not an empty successful
reply.

## Local sandbox and cwd policy

Sandbox and cwd are local bridge configuration, not caller-controlled peer
content. A configuration profile binds an endpoint to:

```text
allowed_cwd_roots: absolute local directories
default_cwd: one directory under an allowed root
sandbox: read_only
approval_mode: deny_all
max_text_bytes: bounded release value (64 KiB maximum)
turn_timeout_ms: bounded release value
drain_timeout_ms: bounded release value
```

The bridge validates that the configured cwd is absolute, exists, is a
directory, and resolves under an allowed local root. It does not accept cwd,
workspace paths, sandbox names, model/provider choices, or approval settings
from `peer_text`. A start/attach uses only the validated local profile.

`Sandbox.read_only` and `ApprovalMode.deny_all` are the conservative public
SDK controls. The bridge protocol exposes no caller-controlled command
execution, file upload/download, image input, skill/mention input, MCP server,
plugin, or tool-control operation. `read_only` is intended to prevent writes
and `deny_all` to prevent approval/escalation interaction; neither is a proof
that zero read-only commands or other Codex tools can execute after a peer
prompt. If the SDK asks for an unsupported escalation or control operation,
the bridge fails the turn closed and returns a bounded error. This is a
Telegraph policy requirement, not a claim that the OpenAI SDK docs guarantee
that all internal Codex tools can never run.

No credential, login flow, or remote endpoint is configured through JSONL.
Local Codex authentication and its storage remain the user's existing Codex
configuration and are outside this bridge contract.

Peer text is untrusted input. A malicious or merely surprising peer prompt may
induce the local Codex agent to read permitted workspace/configuration data,
invoke a locally allowed read-only command or tool, and include sensitive
content in its final response. The local owner chooses the endpoint's cwd,
allowed roots, sandbox, and approval profile; the default is the smallest
read-only root practical for the task, or a stricter isolated directory when
no local data should be exposed. Endpoint setup UX must warn that peer text is
untrusted and that Codex's local policy governs tool behavior. Audit records
the selected policy and rejection/failure class, never the prompt or returned
data. A real-SDK acceptance test must observe and document permitted local
tool behavior rather than asserting that all command execution is impossible.

## Backpressure, timeout, cancellation, and failure

The first implementation must enforce all limits before invoking the SDK:

- one active turn and at most eight queued peer messages per endpoint;
- at most 32 queued peer messages across the bridge;
- a 128 KiB maximum JSONL line and a 64 KiB maximum plain-text payload;
- one bounded turn timeout (release default to be selected and pinned, with a
  hard upper bound of 15 minutes) and a bounded five-second interrupt grace;
- one bounded drain timeout; no busy-loop retries.

If a queue is full, the bridge returns `backpressure` with `retryable=true`
without accepting or running the message. Rust applies its own bounded retry
policy and jitter. It does not retry a request merely because a model turn
was slow.

On timeout, the bridge calls `AsyncTurnHandle.interrupt()`, waits only for the
interrupt grace, and returns `timeout` if the turn is known to have stopped.
If completion cannot be determined, it returns `turn_outcome_unknown` and
marks the message unknown; the same message ID is never automatically run a
second time. On explicit cancellation, a queued message is removed, while an
active message follows the same interrupt path and returns `cancelled` only
when the terminal state is known.

The local journal records only endpoint/message IDs, a keyed or otherwise
privacy-reviewed text digest, state (`queued`, `started`, `completed`,
`cancelled`, `failed`, or `unknown`), and timestamps. It does not persist
prompt or response plaintext by default. A completed response may be cached in
memory until it is returned; after a restart, a completed message without a
persisted response returns `already_completed` rather than running again. This
preserves idempotency and at-most-once Codex input at the cost of requiring a
new, explicitly chosen message ID when a caller needs a new attempt.

For an admitted `peer_text`, the bridge durably commits the `(endpoint,
message_id, text_digest, state=queued)` record before queueing it. Immediately
before the first SDK turn-dispatch call, it durably commits the same record with
`state=started`; the SDK call is not made before that commit succeeds. A crash
after the `started` commit and before or during SDK dispatch is conservatively
classified as `unknown` and is never automatically replayed, even if dispatch
may not have happened. The loss of a possible response is preferred to a
second Codex user turn. The journal transaction and its crash-recovery test
must demonstrate this ordering.

### Idempotency

- `start` and `attach` are idempotent by endpoint handle.
- `peer_text` is idempotent by `(endpoint, message_id)`. The same digest
  returns the cached terminal result or terminal status; a different digest
  returns `idempotency_conflict` and is never run.
- A message marked `started` when the process crashes becomes `unknown` after
  restart. It is not replayed automatically, because the SDK may have already
  committed the user turn. A new message ID is required for a deliberate retry.
- Duplicate `cancel` and `shutdown` operations are harmless and return the
  current terminal state.

These rules are local bridge idempotency. They do not replace the R4
transport-level `delivery_id`, inner `message_id`, or encrypted receipt
semantics; Rust remains responsible for correlating those states.

### Crash and restart

Rust treats bridge EOF, invalid protocol output, non-zero exit, and health
deadline expiry as a crash. It fails pending responses locally, marks active
turns unknown, and starts a fresh bridge only under a bounded restart budget.
The supervisor never sends relay data, a real thread ID, or credentials to the
replacement process. It replays only safe lifecycle operations (`health`, then
`attach` for known local endpoints); it never replays an uncertain
`peer_text`.

After repeated failures the bridge enters `degraded` and stops accepting new
peer text until explicit local recovery. A relay timeout or Rust process crash
must not be interpreted as Codex turn completion. The local audit records
`bridge_crash`, `bridge_restart`, `turn_outcome_unknown`, and the final error
class without plaintext.

## Performance budget

These are release gates to measure, not observations about an unimplemented
bridge or predictions of model latency. Codex inference, upstream service
latency, and a user-visible model turn are excluded from the local adapter
overhead numbers.

- One warm bridge process is shared by the local OS user/daemon; no Python or
  Codex process is spawned per peer message.
- For a valid idle `health` request and for enqueue/response control traffic
  carrying up to 16 KiB of text, Rust-to-bridge JSONL overhead is p95 <= 5 ms
  and p99 <= 20 ms on the supported two-vCPU client profile.
- From child spawn to `health(status=ready)`, bridge startup is p95 <= 3 s
  when the pinned SDK/runtime is installed and local Codex authentication is
  already available. A missing login or slow model request is not hidden in
  this number; it returns a bounded error.
- Bridge adapter RSS while idle is <= 64 MiB, and bridge plus its pinned local
  Codex runtime child is <= 256 MiB. Protocol buffering is bounded by the
  queue and line limits above; it must not grow with an unbounded mailbox.
- One bridge process supports at least 100 accepted local control operations
  per second when no Codex turns are active, while preserving the p95/p99
  overhead targets. Turn throughput is model- and account-dependent and is
  not promised by this ADR.
- A performance run records queue depth, rejected backpressure count, process
  RSS, startup time, JSONL parse/serialize time, and restart time without
  recording text, responses, paths, credentials, or thread IDs.

Failure to meet these budgets does not authorize switching to a WebSocket,
Remote Control, direct App Server CLI, or a broader protocol. It triggers a
Rust/bridge profiling decision or a later ADR.

## Rust trait boundary

The Rust side owns a narrow abstraction equivalent to:

```text
trait CodexEndpoint {
    start(endpoint: OpaqueEndpoint) -> Result<EndpointState>
    attach(endpoint: OpaqueEndpoint) -> Result<EndpointState>
    send_text(endpoint: OpaqueEndpoint,
              message_id: OpaqueMessageId,
              text: PlainText,
              deadline: MonotonicDeadline) -> Result<PlainTextResponse>
    cancel(request_id: OpaqueRequestId) -> Result<CancelState>
    health() -> Result<BridgeHealth>
    shutdown(mode: ShutdownMode) -> Result<ShutdownState>
}
```

The trait has no `thread_id`, file, command, tool, model-provider, network
endpoint, or generic input/output value. `PythonJsonlBridge` is the first
implementation. A future official Rust SDK implementation can provide the
same operations, preserving the endpoint/message/error semantics and tests.
The trait is not a cross-harness IR and must not grow to expose arbitrary
Codex internals.

## Version pins and support matrix

Release artifacts must contain a lockfile with exact hashes for Python,
`openai-codex`, and its matching published runtime package. The bridge uses
the SDK's pinned runtime by default. A `CodexConfig(codex_bin=...)` override is
development-only, must be explicitly enabled, and is never a release support
path. Prereleases, a floating `latest`, direct App Server CLI invocation,
WebSocket, Remote Control, MCP, and arbitrary existing-TUI attachment are
unsupported.

The version observed in R1 (including its local CLI and registry snapshots) is
not a minimum. Every release records a tested tuple and an explicit result:

| Bridge contract | Python | SDK/runtime | Host | Status |
|---|---|---|---|---|
| v1 | >=3.10, exact patch pinned by release | exact stable `openai-codex` and matching pinned runtime | each OS/architecture with a published runtime and passing smoke/negative tests | supported only when the release record says so |
| v1 | prerelease or unsupported Python | any | any | unsupported |
| v1 | any | unpinned SDK, mismatched runtime, or arbitrary `codex_bin` | any | unsupported |
| v1 | any | stable SDK via this bridge | existing interactive TUI or remote endpoint | unsupported; companion-owned threads only |

The support floor is the exact tested release tuple, not a number inferred
from current documentation, PyPI/npm observations, or the local workstation.
An SDK upgrade requires a fresh official-source review, fake-bridge suite,
real local smoke test, sandbox/cwd test, crash/idempotency test, and rollback
plan. If the SDK removes a required public method or changes the pinned
runtime relationship, the bridge is not silently adapted through private
protocol calls.

## Fake bridge contract and acceptance tests

The Rust client and daemon must have a deterministic fake bridge implementing
JSONL v1. It must never start Codex and must reject any field containing a
thread ID, path, credential, command, file, image, or tool request. The fake
bridge test contract covers at least:

1. `health`, `start`, and `attach` success; repeated lifecycle calls are
   idempotent and endpoint-scoped.
2. One `peer_text` produces exactly one `response` with the configured final
   plain text; no intermediate item or tool event crosses the wire.
3. A malformed line, duplicate key, unknown required field, invalid endpoint,
   non-string text, oversized line, and oversized text produce bounded errors.
4. FIFO ordering, per-endpoint queue capacity, global capacity, and
   `backpressure` behavior are deterministic.
5. Duplicate message ID with the same text is idempotent; the same ID with a
   different text is `idempotency_conflict` and never invokes the fake turn.
6. Queued cancellation, active cancellation, timeout, interrupt grace, and
   unknown outcome have distinct terminal states.
7. EOF/crash during queued, active, and completed work exercises restart;
   uncertain work is not replayed, while safe lifecycle re-attach is replayed.
8. `shutdown(drain)` and `shutdown(now)` are bounded and idempotent.
9. Captured JSONL, stderr, audit events, and metrics contain no real thread ID,
   cwd, workspace path, plaintext, response, credentials, command, or tool
   arguments.
10. A replacement Rust implementation behind `CodexEndpoint` passes the same
    contract without changing the Telegraph peer protocol.

The fake contract is necessary for Rust protocol regression tests but cannot
substitute for real-SDK acceptance: it cannot establish stable SDK support,
bundled-runtime compatibility, final-response behavior, or local Codex tool
semantics. Real-SDK acceptance must add a local start/resume smoke test, one
new turn per peer message, `TurnResult.final_response` extraction, exact
runtime/version-pin verification, durable-started-before-dispatch crash
testing, and read-only cwd enforcement. It must attempt representative write
requests and assert that writes/escalation approvals are rejected under the
selected profile; it must also observe/document whether locally permitted
read-only commands or tools can run, without claiming zero command execution.
Timeout/interrupt behavior, endpoint UX warning, and the selected local
sandbox policy are release gates. These tests are future gates, not evidence
that an implementation already exists.

## Audit, privacy, and security boundaries

Bridge-local audit events are limited to:

```text
bridge_start | bridge_ready | endpoint_start | endpoint_attach |
peer_queued | peer_started | peer_completed | peer_cancelled |
peer_failed | bridge_crash | bridge_restart | bridge_shutdown
```

Each event may contain only opaque local endpoint/request/message IDs, state,
error code, retry count, queue depth, and monotonic/wall-clock timestamps.
Text is not logged. Cwd, workspace names, thread IDs, model prompts, model
responses, command output, file contents, tool arguments, API keys, login
tokens, cookies, and full exception strings are prohibited. Any digest or
response retention requires a separate privacy decision and secure local
storage review.

The bridge has no remote telemetry and no relay credentials. The Rust relay
adapter receives only the opaque encrypted Telegraph envelope defined by R4;
the bridge is never a relay shortcut. A compromised local OS/process remains
outside the R4 endpoint threat guarantee, but a bridge must not widen that
boundary by exposing a network listener or a generic control surface.

## Consequences

Benefits:

- Rust keeps the latency-sensitive protocol, bounded queues, audit, and
  supervision in one small native component.
- One warm Python process avoids per-message interpreter/CLI startup while
  using the only currently accepted stable SDK route.
- A narrow stdio seam prevents thread IDs, files, commands, and tool control
  from becoming accidental Telegraph protocol fields.
- The public SDK's thread/turn/final-response surface is replaceable by a
  future official Rust SDK without rewriting peer transport semantics.

Costs and risks:

- The bridge adds a Python runtime and a separate release/pinning surface.
- A crash after turn dispatch can leave a deliberately unknown outcome; the
  design chooses no duplicate Codex input over automatic replay.
- `Sandbox.read_only` and `deny_all` require real acceptance tests; the public
  docs do not prove that they disable every internal tool path.
- The companion route remains conditional and does not satisfy a requirement
  for native existing-TUI attachment. The unsupported boundary is intentional.
- SDK/runtime upgrades can change behavior; exact pins and a rollback path are
  mandatory.

## Implementation gates and claims policy

Before implementation or release, the team must close R1's companion-route
decision and R4's exact protocol, license/support, persistence, privacy, and
independent-review conditions. It must pass the fake bridge contract and the
real-SDK local acceptance suite for every declared support tuple.

Until those gates close, do not claim that Telegraph has a Codex bridge, can
inject peer text into an arbitrary existing TUI, can observe or control
`429`-class events, provides E2EE, supports remote-control/WebSocket/MCP
ingress, or has a supported minimum Codex CLI version.
