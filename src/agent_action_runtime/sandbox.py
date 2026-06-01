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


def read_text_file(
    raw_path: str,
    context: RuntimeContext,
) -> str:
    path = resolve_workspace_path(raw_path, context)

    if not path.exists():
        raise SandboxError(
            "File does not exist",
            code="filesystem.file_not_found",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    if not path.is_file():
        raise SandboxError(
            "Path not a file",
            code="filesystem.not_a_file",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    file_size = path.stat().st_size

    if file_size > context.limits.max_file_size_bytes:
        raise SandboxError(
            "File exceeds max file size",
            code="filesystem.file_too_large",
            details={
                "path": raw_path,
                "resolved_path": str(path),
                "file_size": file_size,
                "max_file_size": context.limits.max_file_size_bytes,
            },
        )

    return path.read_text(encoding="utf-8")


def write_text_file(
    raw_path: str, content: str, context: RuntimeContext, *, overwrite: bool = False
) -> None:
    if len(content) > context.limits.max_write_chars:
        raise SandboxError(
            "Content exceeds max file write size",
            code="filesystem.write_too_large",
            details={
                "path": raw_path,
                "content_size": len(content),
                "max_write_chars": context.limits.max_write_chars,
            },
        )

    path = resolve_workspace_path(raw_path, context)

    if path.exists() and not overwrite:
        raise SandboxError(
            "File already exists",
            code="filesystem.file_exists",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    if path.exists() and not path.is_file():
        raise SandboxError(
            "File is not a file",
            code="filesystem.not_a_file",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def list_directory(
    raw_path: str,
    context: RuntimeContext,
) -> list[str]:
    path = resolve_workspace_path(raw_path, context)

    if not path.exists():
        raise SandboxError(
            "Directory does not exist",
            code="filesystem.directory_not_found",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    if not path.is_dir():
        raise SandboxError(
            "Path is not a dir",
            code="filesystem.not_a_directory",
            details={
                "path": raw_path,
                "resolved_path": str(path),
            },
        )

    return sorted(child.name for child in path.iterdir())
