import subprocess
import time

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import Observation
from agent_action_runtime.errors import ExecutionError
from agent_action_runtime.filesystem.sandbox import resolve_workspace_path
from agent_action_runtime.shell.parser import SHELL_CONTROL_TOKENS, parse_command


TRUSTED_SHELL_PATH = "/usr/bin:/bin"


def run_shell_command(command: str, context: RuntimeContext) -> Observation:
    parts = parse_command(command)
    validate_shell_arguments(parts, context)
    started = time.monotonic()

    try:
        completed = subprocess.run(
            parts,
            cwd=context.normalized_workspace(),
            env=build_shell_environment(),
            capture_output=True,
            text=True,
            timeout=context.limits.shell_timeout_seconds,
            check=False,
        )

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, stderr, truncated = truncate_shell_output(
            completed.stdout,
            completed.stderr,
            context.limits.max_output_chars,
        )

        return Observation(
            data={
                "command": command,
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
        stdout = decode_timeout_output(error.stdout)
        stderr = decode_timeout_output(error.stderr)
        stdout, stderr, truncated = truncate_shell_output(
            stdout,
            stderr,
            context.limits.max_output_chars,
        )

        return Observation(
            data={
                "command": command,
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
                "command": command,
                "error": str(error),
            },
        ) from error


def validate_shell_arguments(parts: list[str], context: RuntimeContext) -> None:
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


def build_shell_environment() -> dict[str, str]:
    return {
        "PATH": TRUSTED_SHELL_PATH,
        "LC_ALL": "C.UTF-8",
    }


def truncate_shell_output(
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


def decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return value
