# Design

`agent-action-runtime` is a minimal runtime kernel for structured agent actions.

It deliberately stops before agent orchestration. There is no LLM call, no planning loop, no memory system, and no prompt construction. The runtime receives one action request and returns one structured result.

![agent-action-runtime pipeline](assets/runtime-pipeline.png)

## Pipeline

```text
ActionRequest
-> schema validation
-> runtime argument validation
-> policy decision
-> controlled execution
-> ActionResult
-> TraceEvent
-> replay
```

## Core Contracts

`ActionRequest` is the input contract. It contains:

- `run_id`
- `tool`
- `args`
- optional `metadata`

`PolicyDecision` records whether an action is:

- `allowed`
- `blocked`
- `requires_approval`

`ActionResult` is the output contract. It records:

- status
- policy decision
- optional observation
- human-readable error
- machine-readable `error_code`
- structured `error_details`

`TraceEvent` is the audit/replay contract. It captures the input action, policy decision, result status, result payload, observation summary, and error.

## Policy Layer

The policy layer decides whether an action may run before execution starts.

Policy profiles provide coarse runtime modes:

- `default`
- `readonly`
- `no_shell`

Filesystem policy checks:

- path must stay inside the workspace root
- sensitive filenames are blocked on requested and resolved paths
- sensitive suffixes are blocked on requested and resolved paths
- sensitive filenames and suffixes are filtered out of directory listings

Shell policy checks:

- command must be allowlisted
- destructive commands are blocked
- network commands require approval
- path-like operands must pass workspace and requested/resolved sensitive-file checks

## Sandbox Layer

The filesystem sandbox resolves user-provided paths against the workspace root and rejects path escapes after resolution.

The sensitive-file policy checks both the requested path name and the resolved target name. This prevents a harmless-looking symlink such as `alias` from bypassing a `.env` block.

The shell runner does not invoke a shell. It parses commands with `shlex`, runs with `shell=False`, uses the workspace as `cwd`, uses a fixed trusted `PATH`, and checks path-like operands through the same workspace and requested/resolved sensitive-file policy used by direct filesystem actions.

## Execution Layer

Execution only happens after policy returns `allowed`.

Supported execution tools:

- read file
- write file
- list directory
- shell command

Execution returns an `Observation`, which contains structured data and a short summary.

## Trace And Replay

Each runtime run can append a JSONL `TraceEvent`.

Replay reads a trace, rebuilds each action, runs it again, and compares stable fields:

- result status
- decision status
- decision policy

Replay intentionally avoids strict full-observation comparison because file content, timing, and shell output can be environment-dependent.
