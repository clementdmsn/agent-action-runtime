from pathlib import Path

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import (
    DecisionStatus,
    ListDirArgs,
    Observation,
    ReadFileArgs,
    ToolName,
    WriteFileArgs,
    WriteMode,
)
from agent_action_runtime.errors import ExecutionError, SandboxError
from agent_action_runtime.filesystem.operations import (
    list_directory,
    read_text_file,
    write_text_file,
)
from agent_action_runtime.filesystem.sensitivity import SensitiveFilePolicy
from agent_action_runtime.shell.runner import run_shell_command
from agent_action_runtime.validation import PreparedAction


class ActionExecutor:
    def __init__(self, *, sensitive_files: SensitiveFilePolicy | None = None) -> None:
        self.sensitive_files = sensitive_files or SensitiveFilePolicy()

    def execute(self, action: PreparedAction, context: RuntimeContext) -> Observation:
        try:
            if action.tool == ToolName.READ_FILE:
                return self.execute_read_file(action, context)
            if action.tool == ToolName.WRITE_FILE:
                return self.execute_write_file(action, context)
            if action.tool == ToolName.LIST_DIR:
                return self.execute_list_dir(action, context)
            if action.tool == ToolName.SHELL:
                return self.execute_shell(action, context)

        except SandboxError as error:
            raise ExecutionError(
                f"{action.tool} blocked by filesystem sandbox",
                code=error.code,
                details={
                    "tool": str(action.tool),
                    "args": action.request.args,
                },
            ) from error

        except UnicodeDecodeError as error:
            raise ExecutionError(
                "File is not valid UTF-8",
                code="runtime.invalid_utf8",
                details={
                    "tool": str(action.tool),
                    "args": action.request.args,
                },
            ) from error

        except OSError as error:
            raise ExecutionError(
                "Could not execute action",
                code="runtime.execution_failed",
                details={
                    "tool": str(action.tool),
                    "args": action.request.args,
                    "error": str(error),
                },
            ) from error

        raise ExecutionError(
            "Unknown tool",
            code="runtime.unknown_tool",
            details={
                "tool": str(action.tool),
            },
        )

    def execute_read_file(self, action: PreparedAction, context: RuntimeContext) -> Observation:
        args = action.args
        if not isinstance(args, ReadFileArgs):
            raise self.invalid_prepared_args(action)

        content = read_text_file(
            raw_path=args.path,
            context=context,
        )

        return Observation(
            data={
                "path": args.path,
                "content": content,
                "bytes": len(content.encode("utf-8")),
            },
            summary=f"Read file: {args.path}",
        )

    def execute_write_file(self, action: PreparedAction, context: RuntimeContext) -> Observation:
        args = action.args
        if not isinstance(args, WriteFileArgs):
            raise self.invalid_prepared_args(action)

        overwrite = args.mode == WriteMode.OVERWRITE

        write_text_file(
            raw_path=args.path, content=args.content, context=context, overwrite=overwrite
        )

        return Observation(
            data={
                "path": args.path,
                "bytes": len(args.content.encode("utf-8")),
                "mode": args.mode,
            },
            summary=f"Wrote file: {args.path}",
        )

    def execute_list_dir(self, action: PreparedAction, context: RuntimeContext) -> Observation:
        args = action.args
        if not isinstance(args, ListDirArgs):
            raise self.invalid_prepared_args(action)

        entries = list_directory(raw_path=args.path, context=context)
        entries = self.filter_sensitive_directory_entries(args.path, entries, context)

        return Observation(
            data={
                "path": args.path,
                "entries": entries,
                "count": len(entries),
            },
            summary=f"Listed directory: {args.path}",
        )

    def execute_shell(self, action: PreparedAction, context: RuntimeContext) -> Observation:
        command = getattr(action.args, "command", None)
        if not isinstance(command, str):
            raise self.invalid_prepared_args(action)

        return run_shell_command(command, context)

    def filter_sensitive_directory_entries(
        self, raw_path: str, entries: list[str], context: RuntimeContext
    ) -> list[str]:
        visible_entries = []

        for entry in entries:
            entry_path = str(Path(raw_path) / entry)
            decision = self.sensitive_files.check_file(entry_path, context)
            if decision.status != DecisionStatus.ALLOWED:
                continue
            visible_entries.append(entry)

        return visible_entries

    def invalid_prepared_args(self, action: PreparedAction) -> ExecutionError:
        return ExecutionError(
            "Prepared action arguments do not match tool",
            code="runtime.invalid_prepared_action",
            details={
                "tool": str(action.tool),
            },
        )
