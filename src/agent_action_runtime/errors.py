from __future__ import annotations


class AgentActionRuntimeError(Exception):
    code = "agent_action_runtime.error"

    def __init__(
        self, message: str, *, code: str | None = None, details: dict | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.code
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }

    def __str__(self) -> str:
        return self.message


class ContractError(AgentActionRuntimeError):
    code = "agent_action_runtime.contract_error"


class PolicyError(AgentActionRuntimeError):
    code = "agent_action_runtime.policy_error"


class SandboxError(AgentActionRuntimeError):
    code = "agent_action_runtime.sandbox_error"


class ExecutionError(AgentActionRuntimeError):
    code = "agent_action_runtime.execution_error"


class TraceError(AgentActionRuntimeError):
    code = "agent_action_runtime.trace_error"


class ReplayError(AgentActionRuntimeError):
    code = "agent_action_runtime.replay_error"
