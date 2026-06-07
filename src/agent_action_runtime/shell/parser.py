import shlex

from agent_action_runtime.errors import ExecutionError


SHELL_CONTROL_TOKENS = {"|", ";", "&&", "||", ">", ">>", "<"}


def parse_command(command: str) -> list[str]:
    try:
        parts = shlex.split(command)
    except ValueError as error:
        raise ExecutionError(
            "Invalid shell command syntax",
            code="shell.invalid_syntax",
            details={
                "command": command,
                "error": str(error),
            },
        ) from error

    if not parts:
        raise ExecutionError(
            "Shell command is empty",
            code="shell.empty_command",
            details={
                "command": command,
            },
        )

    return parts
