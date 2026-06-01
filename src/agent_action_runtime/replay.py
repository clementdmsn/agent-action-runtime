from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_action_runtime.context import ReplayMismatch, ReplayResult, RuntimeContext
from agent_action_runtime.contracts import ActionRequest, TraceEvent
from agent_action_runtime.runtime import ActionRuntime


def replay_trace(trace_path: Path, context: RuntimeContext) -> ReplayResult:
    mismatches: list[ReplayMismatch] = []
    events_replayed = 0

    for line_number, line in enumerate(
        trace_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue

        events_replayed += 1
        raw_event = json.loads(line)
        event = parse_trace_event(raw_event)
        event_id = event.event_id
        run_id = event.run_id

        action = ActionRequest(
            run_id=run_id,
            tool=event.tool,
            args=event.args,
        )
        actual = ActionRuntime().run(action, context)
        expected = event.result

        compare_field(
            mismatches,
            event_id,
            run_id,
            "result.status",
            expected.status,
            actual.status,
        )
        compare_field(
            mismatches,
            event_id,
            run_id,
            "decision.status",
            expected.decision.status,
            actual.decision.status,
        )
        compare_field(
            mismatches,
            event_id,
            run_id,
            "decision.policy",
            expected.decision.policy,
            actual.decision.policy,
        )

    return ReplayResult(
        events_replayed=events_replayed,
        matched=events_replayed - len({mismatch.event_id for mismatch in mismatches}),
        mismatches=mismatches,
    )


def parse_trace_event(data: dict[str, Any]) -> TraceEvent:
    if "result_status" in data:
        return TraceEvent.model_validate(data)

    return TraceEvent.model_validate(
        {
            "event_id": data.get("event_id"),
            "run_id": data.get("run_id") or data.get("event_id") or "legacy-run",
            "timestamp": data["timestamp"],
            "tool": data["tool"],
            "args": data["args"],
            "decision": data["result"]["decision"],
            "result_status": data["result"]["status"],
            "result": data["result"],
            "observation_summary": get_nested(data["result"], "observation", "summary"),
            "error": data["result"].get("error"),
        }
    )


def compare_field(
    mismatches: list[ReplayMismatch],
    event_id: str,
    run_id: str,
    field: str,
    expected: Any,
    actual: Any,
) -> None:
    expected_value = str(expected)
    actual_value = str(actual)

    if expected_value == actual_value:
        return

    mismatches.append(
        ReplayMismatch(
            event_id=event_id,
            run_id=run_id,
            field=field,
            expected=expected_value,
            actual=actual_value,
            reason="Replay result did not match trace",
        )
    )


def get_nested(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current
