# Threat Model

This project is a policy-controlled runtime, not a hardened operating-system sandbox.

## Protected Assets

The V1 runtime is designed to protect:

- files outside the configured workspace root
- sensitive files inside the workspace by name or suffix
- accidental destructive shell commands
- accidental network shell commands without approval
- trace integrity at the schema level

## Trust Boundaries

Inputs crossing into the runtime:

- JSON action requests
- file paths inside action arguments
- shell command strings
- trace files used for replay
- operator-provided runtime context such as workspace and trace paths

The runtime treats action requests as untrusted and validates them before policy evaluation.

`RuntimeContext` is treated as operator-controlled configuration. The workspace boundary applies to paths inside action requests, not to operator-selected trace paths.

## Filesystem Boundary

All filesystem paths are resolved relative to `RuntimeContext.workspace_root`.

The runtime blocks resolved paths that escape the workspace root, including `..` traversal.

Sensitive-file checks apply to both requested names and resolved target names, so symlinks to blocked filenames stay blocked.

Directory listings omit names that match the sensitive-file policy.

Known limits:

- it does not manage Unix file permissions
- it does not isolate users
- it does not protect against host-level race conditions
- it does not create a mount namespace

## Shell Boundary

Shell execution is intentionally narrow:

- commands are allowlisted
- `subprocess.run(..., shell=False)` is used
- the process working directory is the workspace
- command resolution uses a fixed trusted `PATH`
- command operands are checked against the workspace boundary and sensitive-file policy
- command timeout and output limits are enforced

Known limits:

- there is no container isolation
- there is no syscall filtering
- there is no CPU or memory cgroup enforcement
- allowlisted binaries may still have complex behavior
- this is not a complete shell language sandbox

## Network Boundary

Known network commands such as `curl` return `requires_approval`.

## Non-Goals

This project does not attempt to provide:

- Docker isolation
- VM isolation
- multi-user security
- RBAC
- arbitrary untrusted code execution
- malware containment
- data-loss prevention

Use this project as a small control layer for structured actions, not as a security boundary for hostile code.
