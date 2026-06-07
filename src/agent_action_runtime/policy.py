from dataclasses import dataclass

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import (
    ActionRequest,
    DecisionStatus,
    PolicyDecision,
    RiskLevel,
    ToolName,
)
from agent_action_runtime.filesystem.sandbox import is_inside_workspace
from agent_action_runtime.filesystem.sensitivity import (
    SENSITIVE_FILE_NAMES,
    SENSITIVE_FILE_SUFFIXES,
    SensitiveFilePolicy,
)
from agent_action_runtime.shell.policy import (
    ALLOWED_SHELL_COMMANDS,
    DESTRUCTIVE_COMMANDS,
    NETWORK_COMMANDS,
    ShellPolicy,
)


@dataclass
class PolicyEngine:
    allowed_shell_commands = ALLOWED_SHELL_COMMANDS
    destructive_commands = DESTRUCTIVE_COMMANDS
    network_commands = NETWORK_COMMANDS
    sensitive_file_names = SENSITIVE_FILE_NAMES
    sensitive_file_suffixes = SENSITIVE_FILE_SUFFIXES

    def __post_init__(self) -> None:
        self.sensitive_files = SensitiveFilePolicy(
            sensitive_file_names=self.sensitive_file_names,
            sensitive_file_suffixes=self.sensitive_file_suffixes,
        )
        self.shell_policy = ShellPolicy(
            sensitive_files=self.sensitive_files,
            allowed_shell_commands=self.allowed_shell_commands,
            destructive_commands=self.destructive_commands,
            network_commands=self.network_commands,
        )

    def evaluate(self, action: ActionRequest, context: RuntimeContext) -> PolicyDecision:
        profile_decision = self.evaluate_profile(action, context)
        if profile_decision.status != DecisionStatus.ALLOWED:
            return profile_decision

        if action.tool in {
            ToolName.READ_FILE,
            ToolName.WRITE_FILE,
            ToolName.LIST_DIR,
        }:
            return self.evaluate_filesystem(action, context)

        if action.tool == ToolName.SHELL:
            return self.evaluate_shell(action, context)

        return PolicyDecision(
            status=DecisionStatus.BLOCKED,
            reason=f"Unknown tool: {action.tool}",
            policy="tool.unknown",
            risk_level=RiskLevel.HIGH,
        )

    def evaluate_profile(self, action: ActionRequest, context: RuntimeContext) -> PolicyDecision:
        if context.policy_profile == "default":
            return PolicyDecision(
                status=DecisionStatus.ALLOWED,
                reason="Policy profile allows action",
                policy="profile.default",
                risk_level=RiskLevel.LOW,
            )

        if context.policy_profile == "readonly":
            if action.tool in {ToolName.WRITE_FILE, ToolName.SHELL}:
                return PolicyDecision(
                    status=DecisionStatus.BLOCKED,
                    reason=f"Policy profile readonly blocks {action.tool}",
                    policy="profile.readonly",
                    risk_level=RiskLevel.MEDIUM,
                )

            return PolicyDecision(
                status=DecisionStatus.ALLOWED,
                reason="Policy profile readonly allows read-only action",
                policy="profile.readonly",
                risk_level=RiskLevel.LOW,
            )

        if context.policy_profile == "no_shell":
            if action.tool == ToolName.SHELL:
                return PolicyDecision(
                    status=DecisionStatus.BLOCKED,
                    reason="Policy profile no_shell blocks shell",
                    policy="profile.no_shell",
                    risk_level=RiskLevel.MEDIUM,
                )

            return PolicyDecision(
                status=DecisionStatus.ALLOWED,
                reason="Policy profile no_shell allows non-shell action",
                policy="profile.no_shell",
                risk_level=RiskLevel.LOW,
            )

        return PolicyDecision(
            status=DecisionStatus.BLOCKED,
            reason=f"Unknown policy profile: {context.policy_profile}",
            policy="profile.unknown",
            risk_level=RiskLevel.HIGH,
        )

    def evaluate_filesystem(self, action: ActionRequest, context: RuntimeContext) -> PolicyDecision:
        raw_path = action.args.get("path")

        if not isinstance(raw_path, str):
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason="Missing or invalid path",
                policy="filesystem.invalid_path",
                risk_level=RiskLevel.MEDIUM,
            )

        boundary_decision = self.check_workspace_boundary(raw_path, context)

        if boundary_decision.status != DecisionStatus.ALLOWED:
            return boundary_decision

        sensitive_decision = self.check_sensitive_file(raw_path, context)

        if sensitive_decision.status != DecisionStatus.ALLOWED:
            return sensitive_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Filesystem action allowed",
            policy="filesystem.allowed",
            risk_level=RiskLevel.LOW,
        )

    def evaluate_shell(self, action: ActionRequest, context: RuntimeContext) -> PolicyDecision:
        command = action.args.get("command")

        if not isinstance(command, str):
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason="Missing or invalid command",
                policy="shell.invalid_command",
                risk_level=RiskLevel.MEDIUM,
            )

        return self.shell_policy.evaluate(command, context)

    def check_workspace_boundary(self, raw_path: str, context: RuntimeContext) -> PolicyDecision:
        workspace = context.normalized_workspace()
        candidate = (workspace / raw_path).resolve()

        if not is_inside_workspace(candidate, workspace):
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason="Path escapes workspace root",
                policy="filesystem.workspace_escape",
                risk_level=RiskLevel.HIGH,
            )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Path is inside workspace root",
            policy="filesystem.workspace_only",
            risk_level=RiskLevel.LOW,
        )

    def check_sensitive_file(
        self, raw_path: str, context: RuntimeContext | None = None
    ) -> PolicyDecision:
        return self.sensitive_files.check_file(raw_path, context)

    def check_sensitive_path_name(self, name: str) -> PolicyDecision:
        return self.sensitive_files.check_path_name(name)
