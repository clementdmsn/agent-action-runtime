from pathlib import Path

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.errors import SandboxError


def is_inside_workspace(
    path: Path,
    workspace: Path,
) -> bool:
    try:
        path.relative_to(workspace)
        return True
    except ValueError:
        return False


def resolve_workspace_path(raw_path: str, context: RuntimeContext) -> Path:
    workspace = context.normalized_workspace()
    candidate = (workspace / raw_path).resolve()

    if not is_inside_workspace(candidate, workspace):
        raise SandboxError(
            "Path escapes workspace root",
            code="filesystem.workspace_escape",
            details={
                "path": raw_path,
                "workspace": str(workspace),
                "resolved_path": str(candidate),
            },
        )

    return candidate
