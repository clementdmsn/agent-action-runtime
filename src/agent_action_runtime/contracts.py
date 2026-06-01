from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from enum import StrEnum


class ToolName(StrEnum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    LIST_DIR = "list_dir"
    SHELL = "shell"


class DecisionStatus(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REQUIRES_APPROVAL = "requires_approval"


class ResultStatus(StrEnum):
    OK = "ok"
    BLOCKED = "blocked"
    REQUIRES_APPROVAL = "requires_approval"
    ERROR = "error"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class WriteMode(StrEnum):
    CREATE = "create"
    OVERWRITE = "overwrite"


class ReadFileArgs(BaseModel):
    path: str


class WriteFileArgs(BaseModel):
    path: str
    content: str
    mode: WriteMode = WriteMode.CREATE


class ListDirArgs(BaseModel):
    path: str = "."


class ShellArgs(BaseModel):
    command: str


class ActionRequest(BaseModel):
    run_id: str
    tool: ToolName
    args: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    status: DecisionStatus
    reason: str
    policy: str
    risk_level: RiskLevel = RiskLevel.LOW


class Observation(BaseModel):
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = None


class ActionResult(BaseModel):
    status: ResultStatus
    decision: PolicyDecision
    observation: Observation | None = None
    error: str | None = None
    error_code: str | None = None
    error_details: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def ok(cls, decision: PolicyDecision, observation: Observation) -> ActionResult:
        return cls(
            status=ResultStatus.OK,
            decision=decision,
            observation=observation,
            error=None,
            error_code=None,
            error_details={},
        )

    @classmethod
    def blocked(
        cls,
        decision: PolicyDecision,
    ) -> ActionResult:
        return cls(
            status=ResultStatus.BLOCKED,
            decision=decision,
            error=decision.reason,
            error_code=decision.policy,
            error_details={},
        )

    @classmethod
    def requires_approval(
        cls,
        decision: PolicyDecision,
    ) -> ActionResult:
        return cls(
            status=ResultStatus.REQUIRES_APPROVAL,
            decision=decision,
            error=decision.reason,
            error_code=decision.policy,
            error_details={},
        )

    @classmethod
    def failed(
        cls,
        decision: PolicyDecision,
        message: str,
        *,
        error_code: str,
        error_details: dict[str, Any] | None = None,
    ) -> ActionResult:
        return cls(
            status=ResultStatus.ERROR,
            decision=decision,
            observation=None,
            error=message,
            error_code=error_code,
            error_details=error_details or {},
        )


class TraceEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    timestamp: datetime
    tool: ToolName
    args: dict[str, Any]
    decision: PolicyDecision
    result_status: ResultStatus
    result: ActionResult
    observation_summary: str | None = None
    error: str | None = None

    @classmethod
    def from_action_result(
        cls,
        action: ActionRequest,
        result: ActionResult,
        *,
        timestamp: datetime,
    ) -> TraceEvent:
        return cls(
            run_id=action.run_id,
            timestamp=timestamp,
            tool=action.tool,
            args=action.args,
            decision=result.decision,
            result_status=result.status,
            result=result,
            observation_summary=result.observation.summary if result.observation else None,
            error=result.error,
        )
