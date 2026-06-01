import json

from typer.testing import CliRunner

from agent_action_runtime.cli import app


def test_cli_run_outputs_json_result(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "notes.txt").write_text("hello", encoding="utf-8")
    action_file = tmp_path / "safe_read.json"
    action_file.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "tool": "read_file",
                "args": {"path": "notes.txt"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            str(action_file),
            "--workspace",
            str(workspace),
            "--json-output",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["observation"]["data"]["content"] == "hello"


def test_cli_run_blocked_result_uses_blocked_exit_code(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    action_file = tmp_path / "blocked.json"
    action_file.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "tool": "read_file",
                "args": {"path": "../outside.txt"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            str(action_file),
            "--workspace",
            str(workspace),
            "--json-output",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_cli_run_requires_approval_uses_approval_exit_code(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    action_file = tmp_path / "approval.json"
    action_file.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "tool": "shell",
                "args": {"command": "curl https://example.com"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            str(action_file),
            "--workspace",
            str(workspace),
            "--json-output",
        ],
    )

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["status"] == "requires_approval"


def test_cli_policy_profile_option_is_applied(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    action_file = tmp_path / "write.json"
    action_file.write_text(
        json.dumps(
            {
                "run_id": "run-1",
                "tool": "write_file",
                "args": {"path": "generated.txt", "content": "hello"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "run",
            str(action_file),
            "--workspace",
            str(workspace),
            "--policy-profile",
            "readonly",
            "--json-output",
        ],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["decision"]["policy"] == "profile.readonly"
