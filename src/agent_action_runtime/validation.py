from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError as PydanticValidationError

from agent_action_runtime.contracts import (
    ActionRequest,
    ListDirArgs,
    ReadFileArgs,
    ShellArgs,
    ToolName,
    WriteFileArgs,
)
from agent_action_runtime.errors import ExecutionError


PreparedArgs = ReadFileArgs | WriteFileArgs | ListDirArgs | ShellArgs


@dataclass(frozen=True)
class PreparedAction:
    request: ActionRequest
    args: PreparedArgs

    @property
    def run_id(self) -> str:
        return self.request.run_id

    @property
    def tool(self) -> ToolName:
        return self.request.tool


def prepare_action(action: ActionRequest) -> PreparedAction:
    try:
        if action.tool == ToolName.READ_FILE:
            return PreparedAction(action, ReadFileArgs.model_validate(action.args))
        if action.tool == ToolName.WRITE_FILE:
            return PreparedAction(action, WriteFileArgs.model_validate(action.args))
        if action.tool == ToolName.LIST_DIR:
            return PreparedAction(action, ListDirArgs.model_validate(action.args))
        if action.tool == ToolName.SHELL:
            return PreparedAction(action, ShellArgs.model_validate(action.args))

    except PydanticValidationError as error:
        raise ExecutionError(
            "Invalid action arguments",
            code="runtime.invalid_action_args",
            details={
                "tool": str(action.tool),
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
