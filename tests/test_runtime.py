import json

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import ActionRequest, ResultStatus, TraceEvent
from agent_action_runtime.runtime import ActionRuntime


def run_action(tmp_path, tool: str, args: dict):
    action = ActionRequest(run_id="run-1", tool=tool, args=args)
    context = RuntimeContext(workspace_root=tmp_path)
    return ActionRuntime().run(action, context)


def test_runtime_reads_file(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")

    result = run_action(tmp_path, "read_file", {"path": "notes.txt"})

    assert result.status == ResultStatus.OK
    assert result.observation is not None
    assert result.observation.data["content"] == "hello"


def test_runtime_writes_file(tmp_path) -> None:
    result = run_action(
        tmp_path,
        "write_file",
        {"path": "generated.txt", "content": "created", "mode": "create"},
    )

    assert result.status == ResultStatus.OK
    assert (tmp_path / "generated.txt").read_text(encoding="utf-8") == "created"


def test_runtime_lists_directory(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")

    result = run_action(tmp_path, "list_dir", {"path": "."})

    assert result.status == ResultStatus.OK
    assert result.observation is not None
    assert result.observation.data["entries"] == ["notes.txt"]


def test_runtime_filters_sensitive_directory_entries(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")

    result = run_action(tmp_path, "list_dir", {"path": "."})

    assert result.status == ResultStatus.OK
    assert result.observation is not None
    assert result.observation.data["entries"] == ["notes.txt"]
    assert result.observation.data["count"] == 1


def test_runtime_blocks_path_escape_before_execution(tmp_path) -> None:
    result = run_action(tmp_path, "read_file", {"path": "../outside.txt"})

    assert result.status == ResultStatus.BLOCKED
    assert result.decision.policy == "filesystem.workspace_escape"


def test_runtime_executes_allowlisted_shell_command(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello\nworld\n", encoding="utf-8")

    result = run_action(tmp_path, "shell", {"command": "wc -l notes.txt"})

    assert result.status == ResultStatus.OK
    assert result.observation is not None
    assert result.observation.data["exit_code"] == 0
    assert result.observation.data["stdout"] == "2 notes.txt\n"


def test_runtime_does_not_resolve_shell_command_from_workspace_path(tmp_path, monkeypatch) -> None:
    fake_cat = tmp_path / "cat"
    fake_cat.write_text("#!/bin/sh\necho HIJACKED\n", encoding="utf-8")
    fake_cat.chmod(0o755)
    (tmp_path / "notes.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setenv("PATH", ".:/usr/bin:/bin")

    result = run_action(tmp_path, "shell", {"command": "cat notes.txt"})

    assert result.status == ResultStatus.OK
    assert result.observation is not None
    assert result.observation.data["stdout"] == "hello\n"


def test_runtime_blocks_shell_path_escape_before_execution(tmp_path) -> None:
    result = run_action(tmp_path, "shell", {"command": "cat ../outside.txt"})

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.workspace_escape"


def test_runtime_blocks_shell_sensitive_file_before_execution(tmp_path) -> None:
    result = run_action(tmp_path, "shell", {"command": "cat .env"})

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.sensitive_name"


def test_runtime_blocks_reading_symlink_to_sensitive_file(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "alias").symlink_to(".env")

    result = run_action(tmp_path, "read_file", {"path": "alias"})

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.sensitive_name"


def test_runtime_blocks_writing_symlink_to_sensitive_file(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "alias").symlink_to(".env")

    result = run_action(
        tmp_path,
        "write_file",
        {"path": "alias", "content": "CHANGED", "mode": "overwrite"},
    )

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.sensitive_name"
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "SECRET"


def test_runtime_blocks_shell_reading_symlink_to_sensitive_file(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "alias").symlink_to(".env")

    result = run_action(tmp_path, "shell", {"command": "cat alias"})

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.sensitive_name"


def test_runtime_blocks_dash_prefixed_symlink_operand_after_option_separator(
    tmp_path,
) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "-alias").symlink_to(".env")

    result = run_action(tmp_path, "shell", {"command": "cat -- -alias"})

    assert result.status == ResultStatus.BLOCKED
    assert result.error_code == "filesystem.sensitive_name"


def test_runtime_writes_trace_event(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    trace_path = tmp_path / "trace.jsonl"
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "notes.txt"})
    context = RuntimeContext(workspace_root=tmp_path, trace_path=trace_path)

    result = ActionRuntime().run(action, context)

    assert result.status == ResultStatus.OK
    events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    event = TraceEvent.model_validate(events[0])
    assert event.run_id == "run-1"
    assert event.tool == "read_file"
    assert event.result.status == "ok"
    assert event.result_status == "ok"
