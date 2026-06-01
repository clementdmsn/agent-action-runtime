import json

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import ActionRequest
from agent_action_runtime.replay import replay_trace
from agent_action_runtime.runtime import ActionRuntime


def test_replay_trace_matches_recorded_result(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "notes.txt"})
    context = RuntimeContext(workspace_root=tmp_path, trace_path=trace_path)
    ActionRuntime().run(action, context)

    result = replay_trace(trace_path, RuntimeContext(workspace_root=tmp_path))

    assert result.events_replayed == 1
    assert result.matched == 1
    assert result.mismatches == []


def test_replay_trace_reports_mismatch(tmp_path) -> None:
    trace_path = tmp_path / "trace.jsonl"
    trace_path.write_text(
        json.dumps(
            {
                "event_id": "event-1",
                "run_id": "run-1",
                "timestamp": "2026-05-31T00:00:00Z",
                "tool": "read_file",
                "args": {"path": "missing.txt"},
                "decision": {
                    "status": "allowed",
                    "reason": "Filesystem action allowed",
                    "policy": "filesystem.allowed",
                    "risk_level": "low",
                },
                "result_status": "ok",
                "result": {
                    "status": "ok",
                    "decision": {
                        "status": "allowed",
                        "reason": "Filesystem action allowed",
                        "policy": "filesystem.allowed",
                        "risk_level": "low",
                    },
                    "observation": None,
                    "error": None,
                    "error_code": None,
                    "error_details": {},
                },
                "observation_summary": None,
                "error": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = replay_trace(trace_path, RuntimeContext(workspace_root=tmp_path))

    assert result.events_replayed == 1
    assert result.matched == 0
    assert result.mismatches


def test_replay_trace_reads_current_trace_schema(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    action = ActionRequest(run_id="run-current", tool="read_file", args={"path": "notes.txt"})
    context = RuntimeContext(workspace_root=tmp_path, trace_path=trace_path)
    ActionRuntime().run(action, context)

    event = json.loads(trace_path.read_text(encoding="utf-8").splitlines()[0])

    assert event["run_id"] == "run-current"
    assert event["result_status"] == "ok"
    assert event["observation_summary"] == "Read file: notes.txt"
    assert event["result"]["error_code"] is None
