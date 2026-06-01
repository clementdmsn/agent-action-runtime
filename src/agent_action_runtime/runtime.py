from __future__ import annotations

import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from pydantic import ValidationError as PydanticValidationError

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import (
    ActionRequest,
    ActionResult,
    DecisionStatus,
    ListDirArgs,
    Observation,
    PolicyDecision,
    ReadFileArgs,
    RiskLevel,
    ShellArgs,
    TraceEvent,
    ToolName,
    WriteFileArgs,
    WriteMode,
)
from agent_action_runtime.errors import AgentActionRuntimeError, ExecutionError, SandboxError
from agent_action_runtime.policy import PolicyEngine
from agent_action_runtime.sandbox import (
    list_directory,
    read_text_file,
    resolve_workspace_path,
    write_text_file,
)

SHELL_CONTROL_TOKENS = {"|", ";", "&&", "||", ">", ">>", "<"}
TRUSTED_SHELL_PATH = "/usr/bin:/bin"


class ActionRuntime:
    # policy_engine: PolicyEngine()
    # filesystem: FileSystemSandbox()
    # command_runner: CommandRunner()
    # trace_writer: TraceWriter | None

    def __init__(self):
        self.policy_engine = PolicyEngine()

    def run(self, action: ActionRequest, context: RuntimeContext) -> ActionResult:
        decision = self.evaluate_policy(action, context)

        if decision.status == DecisionStatus.BLOCKED:
            result = self.handle_blocked(action, decision)
            self.write_trace(action, result, context)
            return result
        if decision.status == DecisionStatus.REQUIRES_APPROVAL:
            result = self.handle_requires_approval(action, decision)
            self.write_trace(action, result, context)
            return result

        try:
            observation = self.execute(action, context)
            result = ActionResult.ok(decision, observation)
            self.write_trace(action, result, context)
            return result

        except ExecutionError as error:
            result = self.handle_error(action, decision, error)
            self.write_trace(action, result, context)
            return result

        except AgentActionRuntimeError as error:
            runtime_error = ExecutionError(
                str(error),
                code=error.code,
                details={
                    "error": str(error),
                    "error_type": type(error).__name__,
                },
            )

            result = self.handle_error(action, decision, runtime_error)
            self.write_trace(action, result, context)
            return result

    def validate_action(self, action: ActionRequest) -> ActionResult:
        try:
            if action.tool == ToolName.READ_FILE:
                ReadFileArgs.model_validate(action.args)
                return
            if action.tool == ToolName.WRITE_FILE:
                WriteFileArgs.model_validate(action.args)
                return
            if action.tool == ToolName.LIST_DIR:
                ListDirArgs.model_validate(action.args)
                return
            if action.tool == ToolName.SHELL:
                ShellArgs.model_validate(action.args)
                return

        except PydanticValidationError as error:
            raise ExecutionError(
                "Invalid action arguments",
                code="runtime.invalid_action_args",
                details={
                    "tools": str(action.tool),
                    "error": str(error),
                },
            ) from error

        raise ExecutionError(
            "Unknown tool",
            details={
                "tools": str(action.tool),
            },
        )

    def evaluate_policy(self, action: ActionRequest, context: RuntimeContext) -> PolicyDecision:
        try:
            self.validate_action(action)

        except ExecutionError as error:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=str(error),
                policy=error.code,
                risk_level=RiskLevel.LOW,
            )

        return self.policy_engine.evaluate(action, context)

    def execute(self, action: ActionRequest, context: RuntimeContext) -> Observation:
        handlers: dict[ToolName, Callable[[ActionRequest, RuntimeContext], Observation]] = {
            ToolName.READ_FILE: self.execute_read_file,
            ToolName.WRITE_FILE: self.execute_write_file,
            ToolName.LIST_DIR: self.execute_list_dir,
            ToolName.SHELL: self.execute_shell,
        }

        try:
            handler = handlers[action.tool]

        except KeyError:
            raise ExecutionError(
                "Unknown tool",
                code="runtime.unknown_tool",
                details={
                    "tool": str(action.tool),
                },
            )

        return handler(action, context)

    def execute_read_file(self, action: ActionRequest, context: RuntimeContext) -> Observation:
        try:
            args = ReadFileArgs.model_validate(action.args)

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

        except PydanticValidationError as error:
            raise ExecutionError(
                "Invalid read_file arguments",
                code="runtime.invalid_read_file_args",
                details={
                    "error": str(error),
                },
            ) from error

        except SandboxError as error:
            raise ExecutionError(
                "read_file blocked by filesystem sandbox",
                code=error.code,
                details={
                    "path": action.args.get("path"),
                },
            ) from error

        except UnicodeDecodeError as error:
            raise ExecutionError(
                "File is not valid UTF-8",
                code="runtime.invalid_utf8",
                details={
                    "path": action.args.get("path"),
                },
            ) from error

        except OSError as error:
            raise ExecutionError(
                "Could not read file",
                code="runtime.read_file_failed",
                details={
                    "path": action.args.get("path"),
                    "error": str(error),
                },
            ) from error

    def execute_write_file(self, action: ActionRequest, context: RuntimeContext) -> Observation:
        try:
            args = WriteFileArgs.model_validate(action.args)

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

        except PydanticValidationError as error:
            raise ExecutionError(
                "Invalid write_file arguments",
                code="runtime.invalid_write_file_args",
                details={
                    "error": str(error),
                },
            ) from error

        except SandboxError as error:
            raise ExecutionError(
                "write_file blocked by filesystem sandbox",
                code=error.code,
                details={
                    "path": action.args.get("path"),
                },
            ) from error

        except OSError as error:
            raise ExecutionError(
                "Could not write file",
                code="runtime.write_file_failed",
                details={
                    "path": action.args.get("path"),
                    "error": str(error),
                },
            ) from error

    def execute_list_dir(self, action: ActionRequest, context: RuntimeContext) -> Observation:
        try:
            args = ListDirArgs.model_validate(action.args)

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

        except PydanticValidationError as error:
            raise ExecutionError(
                "Invalid list_dir arguments",
                code="runtime.invalid_list_dir_args",
                details={
                    "error": str(error),
                },
            ) from error

        except SandboxError as error:
            raise ExecutionError(
                "list_dir blocked by filesystem sandbox",
                code=error.code,
                details={
                    "path": action.args.get("path"),
                },
            ) from error

        except OSError as error:
            raise ExecutionError(
                "Could not list directory",
                code="runtime.list_dir_failed",
                details={
                    "path": action.args.get("path"),
                    "error": str(error),
                },
            ) from error

    def filter_sensitive_directory_entries(
        self, raw_path: str, entries: list[str], context: RuntimeContext
    ) -> list[str]:
        visible_entries = []

        for entry in entries:
            entry_path = str(Path(raw_path) / entry)
            decision = self.policy_engine.check_sensitive_file(entry_path, context)
            if decision.status != DecisionStatus.ALLOWED:
                continue
            visible_entries.append(entry)

        return visible_entries

    def execute_shell(self, action: ActionRequest, context: RuntimeContext) -> Observation:
        try:
            args = ShellArgs.model_validate(action.args)
            try:
                parts = shlex.split(args.command)
            except ValueError as error:
                raise ExecutionError(
                    "Invalid shell command syntax",
                    code="runtime.invalid_shell_command_syntax",
                    details={
                        "command": args.command,
                        "error": str(error),
                    },
                ) from error

            if not parts:
                raise ExecutionError(
                    "Shell command is empty",
                    code="runtime.empty_shell_command",
                    details={
                        "command": args.command,
                    },
                )

            self.validate_shell_arguments(parts, context)
            started = time.monotonic()

            try:
                completed = subprocess.run(
                    parts,
                    cwd=context.normalized_workspace(),
                    env=self.build_shell_environment(),
                    capture_output=True,
                    text=True,
                    timeout=context.limits.shell_timeout_seconds,
                    check=False,
                )

                duration_ms = int((time.monotonic() - started) * 1000)
                stdout, stderr, truncated = self.truncate_shell_output(
                    completed.stdout,
                    completed.stderr,
                    context.limits.max_output_chars,
                )

                return Observation(
                    data={
                        "command": args.command,
                        "exit_code": completed.returncode,
                        "stdout": stdout,
                        "stderr": stderr,
                        "duration_ms": duration_ms,
                        "timed_out": False,
                        "truncated": truncated,
                    },
                    summary=f"Shell command exited with code {completed.returncode}",
                )

            except subprocess.TimeoutExpired as error:
                duration_ms = int((time.monotonic() - started) * 1000)
                stdout = self.decode_timeout_output(error.stdout)
                stderr = self.decode_timeout_output(error.stderr)
                stdout, stderr, truncated = self.truncate_shell_output(
                    stdout,
                    stderr,
                    context.limits.max_output_chars,
                )

                return Observation(
                    data={
                        "command": args.command,
                        "exit_code": None,
                        "stdout": stdout,
                        "stderr": stderr,
                        "duration_ms": duration_ms,
                        "timed_out": True,
                        "truncated": truncated,
                    },
                    summary=f"Shell command timed out after {context.limits.shell_timeout_seconds}s",
                )

            except OSError as error:
                raise ExecutionError(
                    "Could not execute shell command",
                    code="runtime.shell_execution_failed",
                    details={
                        "command": args.command,
                        "error": str(error),
                    },
                ) from error

        except PydanticValidationError as error:
            raise ExecutionError(
                "Invalid shell argument",
                code="runtime.invalid_shell_args",
                details={
                    "error": str(error),
                },
            ) from error

        except SandboxError as error:
            raise ExecutionError(
                "shell blocked by filesystem sandbox",
                code=error.code,
                details={
                    "command": action.args.get("command"),
                },
            ) from error

    def validate_shell_arguments(self, parts: list[str], context: RuntimeContext) -> None:
        option_parsing_stopped = False

        for token in parts[1:]:
            if token in SHELL_CONTROL_TOKENS:
                raise ExecutionError(
                    "Shell control syntax is not supported",
                    code="runtime.shell_control_syntax_unsupported",
                    details={
                        "token": token,
                    },
                )

            if token == "--":
                option_parsing_stopped = True
                continue

            if token.startswith("-") and not option_parsing_stopped:
                if "/" in token or "\\" in token or "=" in token:
                    raise ExecutionError(
                        "Shell option syntax is not supported",
                        code="runtime.shell_option_syntax_unsupported",
                        details={
                            "token": token,
                        },
                    )

                continue

            resolve_workspace_path(token, context)

    def build_shell_environment(self) -> dict[str, str]:
        return {
            "PATH": TRUSTED_SHELL_PATH,
            "LC_ALL": "C.UTF-8",
        }

    def truncate_shell_output(
        self,
        stdout: str,
        stderr: str,
        max_output_chars: int,
    ) -> tuple[str, str, bool]:
        truncated = False

        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars]
            truncated = True

        if len(stderr) > max_output_chars:
            stderr = stderr[:max_output_chars]
            truncated = True

        return stdout, stderr, truncated

    def decode_timeout_output(self, value: str | bytes | None) -> str:
        if value is None:
            return ""

        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")

        return value

    def handle_blocked(self, action: ActionRequest, decision: PolicyDecision) -> ActionResult:
        return ActionResult.blocked(decision)

    def handle_requires_approval(
        self, action: ActionRequest, decision: PolicyDecision
    ) -> ActionResult:
        return ActionResult.requires_approval(decision)

    def handle_error(
        self, action: ActionRequest, decision: PolicyDecision, error: AgentActionRuntimeError
    ) -> ActionResult:
        return ActionResult.failed(
            decision,
            str(error),
            error_code=error.code,
            error_details=error.details,
        )

    def write_trace(self, action: ActionRequest, result: ActionResult, context: RuntimeContext):
        trace_path = getattr(context, "trace_path", None)

        if trace_path is None:
            return

        path = Path(trace_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        event = TraceEvent.from_action_result(
            action,
            result,
            timestamp=datetime.now(timezone.utc),
        )

        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False))
            file.write("\n")
