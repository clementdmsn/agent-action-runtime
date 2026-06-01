from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import ActionRequest, DecisionStatus
from agent_action_runtime.policy import PolicyEngine


def evaluate(action: ActionRequest, tmp_path):
    return PolicyEngine().evaluate(action, RuntimeContext(workspace_root=tmp_path))


def evaluate_with_profile(action: ActionRequest, tmp_path, profile: str):
    return PolicyEngine().evaluate(
        action,
        RuntimeContext(workspace_root=tmp_path, policy_profile=profile),
    )


def test_filesystem_action_inside_workspace_is_allowed(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "notes.txt"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.ALLOWED
    assert decision.policy == "filesystem.allowed"


def test_filesystem_path_escape_is_blocked(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "../notes.txt"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.workspace_escape"


def test_sensitive_file_is_blocked(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": ".env"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.sensitive_name"


def test_symlink_to_sensitive_file_is_blocked(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "alias").symlink_to(".env")
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "alias"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.sensitive_name"


def test_destructive_shell_command_is_blocked(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "rm notes.txt"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "shell.destructive_command"


def test_network_shell_command_requires_approval(tmp_path) -> None:
    action = ActionRequest(
        run_id="run-1",
        tool="shell",
        args={"command": "curl https://example.com"},
    )

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.REQUIRES_APPROVAL
    assert decision.policy == "shell.network_requires_approval"


def test_unknown_shell_command_is_blocked(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "python script.py"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "shell.command_not_allowed"


def test_shell_path_escape_is_blocked_by_policy(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "cat ../outside.txt"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.workspace_escape"


def test_shell_sensitive_file_is_blocked_by_policy(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "cat .env"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.sensitive_name"


def test_shell_symlink_to_sensitive_file_is_blocked_by_policy(tmp_path) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "alias").symlink_to(".env")
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "cat alias"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.sensitive_name"


def test_shell_dash_prefixed_symlink_operand_is_checked_after_option_separator(
    tmp_path,
) -> None:
    (tmp_path / ".env").write_text("SECRET", encoding="utf-8")
    (tmp_path / "-alias").symlink_to(".env")
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "cat -- -alias"})

    decision = evaluate(action, tmp_path)

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "filesystem.sensitive_name"


def test_readonly_profile_blocks_write(tmp_path) -> None:
    action = ActionRequest(
        run_id="run-1",
        tool="write_file",
        args={"path": "notes.txt", "content": "hello"},
    )

    decision = evaluate_with_profile(action, tmp_path, "readonly")

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "profile.readonly"


def test_no_shell_profile_blocks_shell(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="shell", args={"command": "wc -l notes.txt"})

    decision = evaluate_with_profile(action, tmp_path, "no_shell")

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "profile.no_shell"


def test_unknown_profile_is_blocked(tmp_path) -> None:
    action = ActionRequest(run_id="run-1", tool="read_file", args={"path": "notes.txt"})

    decision = evaluate_with_profile(action, tmp_path, "strict")

    assert decision.status == DecisionStatus.BLOCKED
    assert decision.policy == "profile.unknown"
