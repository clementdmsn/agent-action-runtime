import pytest
from pydantic import ValidationError

from agent_action_runtime.contracts import (
    ActionRequest,
    ActionResult,
    DecisionStatus,
    Observation,
    PolicyDecision,
    ResultStatus,
    RiskLevel,
    TraceEvent,
    ToolName,
)


def test_action_request_validates_tool_name() -> None:
    action = ActionRequest.model_validate(
        {
            "run_id": "run-1",
            "tool": "read_file",
            "args": {"path": "notes.txt"},
        }
    )

    assert action.tool == ToolName.READ_FILE
    assert action.metadata == {}


def test_action_request_rejects_unknown_tool() -> None:
    with pytest.raises(ValidationError):
        ActionRequest.model_validate(
            {
                "run_id": "run-1",
                "tool": "unknown",
                "args": {},
            }
        )


def test_action_result_ok_keeps_observation() -> None:
    decision = PolicyDecision(
        status=DecisionStatus.ALLOWED,
        reason="allowed",
        policy="test.allowed",
        risk_level=RiskLevel.LOW,
    )
    observation = Observation(data={"value": 1}, summary="done")

    result = ActionResult.ok(decision, observation)

    assert result.status == ResultStatus.OK
    assert result.observation == observation
    assert result.error is None


def test_action_result_blocked_has_no_observation() -> None:
    decision = PolicyDecision(
        status=DecisionStatus.BLOCKED,
        reason="blocked",
        policy="test.blocked",
        risk_level=RiskLevel.HIGH,
    )

    result = ActionResult.blocked(decision)

    assert result.status == ResultStatus.BLOCKED
    assert result.observation is None
    assert result.error == "blocked"
    assert result.error_code == "test.blocked"


def test_action_result_failed_has_structured_error() -> None:
    decision = PolicyDecision(
        status=DecisionStatus.ALLOWED,
        reason="allowed",
        policy="test.allowed",
        risk_level=RiskLevel.LOW,
    )

    result = ActionResult.failed(
        decision,
        "failed",
        error_code="runtime.failed",
        error_details={"path": "notes.txt"},
    )

    assert result.status == ResultStatus.ERROR
    assert result.error == "failed"
    assert result.error_code == "runtime.failed"
    assert result.error_details == {"path": "notes.txt"}


def test_trace_event_can_be_created_from_result() -> None:
    action = ActionRequest(run_id="run-1", tool="list_dir", args={"path": "."})
    decision = PolicyDecision(
        status=DecisionStatus.ALLOWED,
        reason="allowed",
        policy="filesystem.allowed",
        risk_level=RiskLevel.LOW,
    )
    result = ActionResult.ok(decision, Observation(summary="Listed directory: ."))

    event = TraceEvent.from_action_result(
        action,
        result,
        timestamp="2026-05-31T00:00:00Z",
    )

    assert event.run_id == "run-1"
    assert event.tool == ToolName.LIST_DIR
    assert event.result_status == ResultStatus.OK
    assert event.observation_summary == "Listed directory: ."
