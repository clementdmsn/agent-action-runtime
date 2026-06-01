# Demo Walkthrough

This walkthrough covers every example action in `examples/`.

Commands that return `blocked` exit with code `2`. Commands that return `requires_approval` exit with code `3`.

## Safe Actions

Read a file inside the workspace:

```bash
venv/bin/agent-action-runtime run examples/safe_read.json --workspace examples/workspace --json-output
```

Expected status: `ok`

List the workspace:

```bash
venv/bin/agent-action-runtime run examples/safe_list_dir.json --workspace examples/workspace --json-output
```

Expected status: `ok`

Write a generated file inside the workspace:

```bash
venv/bin/agent-action-runtime run examples/safe_write.json --workspace examples/workspace --json-output
```

Expected status: `ok`

Run an allowlisted shell command:

```bash
venv/bin/agent-action-runtime run examples/safe_shell.json --workspace examples/workspace --json-output
```

Expected status: `ok`

## Blocked Filesystem Actions

Reject a path escape:

```bash
venv/bin/agent-action-runtime run examples/blocked_path_escape.json --workspace examples/workspace --json-output || test $? -eq 2
```

Expected status: `blocked`

The policy layer rejects `../outside.txt` because the resolved path escapes the workspace root.

Reject a sensitive filename:

```bash
venv/bin/agent-action-runtime run examples/blocked_sensitive_file.json --workspace examples/workspace --json-output || test $? -eq 2
```

Expected status: `blocked`

The policy layer rejects `.env` before execution.

## Blocked Shell Actions

Reject a destructive command:

```bash
venv/bin/agent-action-runtime run examples/blocked_shell_destructive.json --workspace examples/workspace --json-output || test $? -eq 2
```

Expected status: `blocked`

Reject a shell operand that escapes the workspace:

```bash
venv/bin/agent-action-runtime run examples/blocked_shell_path_escape.json --workspace examples/workspace --json-output || test $? -eq 2
```

Expected status: `blocked`

Reject a shell operand that targets a sensitive filename:

```bash
venv/bin/agent-action-runtime run examples/blocked_shell_sensitive_file.json --workspace examples/workspace --json-output || test $? -eq 2
```

Expected status: `blocked`

Require approval for a network command:

```bash
venv/bin/agent-action-runtime run examples/shell_requires_approval.json --workspace examples/workspace --json-output || test $? -eq 3
```

Expected status: `requires_approval`

## Replay

Replay a recorded trace:

```bash
venv/bin/agent-action-runtime replay examples/trace_demo.jsonl --workspace examples/workspace --json-output
```

Expected result:

```json
{
  "events_replayed": 2,
  "matched": 2,
  "mismatches": []
}
```

Replay rebuilds actions from the trace and compares stable runtime decision fields.

## Policy Profiles

Run the write example under the `readonly` profile:

```bash
venv/bin/agent-action-runtime run examples/safe_write.json --workspace examples/workspace --policy-profile readonly --json-output || test $? -eq 2
```

Expected status: `blocked`

The same `write_file` action that is allowed under the default profile is blocked under `readonly`.
