from dataclasses import dataclass
from pathlib import Path
import shlex

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import (
    ActionRequest,
    DecisionStatus,
    PolicyDecision,
    RiskLevel,
    ToolName,
)
from agent_action_runtime.sandbox import is_inside_workspace

ALLOWED_SHELL_COMMANDS = ["cat", "head", "tail", "wc"]

DESTRUCTIVE_COMMANDS = [
    "rm",
]

NETWORK_COMMANDS = [
    "curl",
]

SENSITIVE_FILE_NAMES = [
    ".env",
    ".env.local",
    "id_rsa",
    "id_ed25519",
]

SENSITIVE_FILE_SUFFIXES = [
    ".pem",
    ".key",
]

SHELL_CONTROL_TOKENS = {"|", ";", "&&", "||", ">", ">>", "<"}


@dataclass
class PolicyEngine:
    allowed_shell_commands = ALLOWED_SHELL_COMMANDS
    destructive_commands = DESTRUCTIVE_COMMANDS
    network_commands = NETWORK_COMMANDS
    sensitive_file_names = SENSITIVE_FILE_NAMES
    sensitive_file_suffixes = SENSITIVE_FILE_SUFFIXES

    def evaluate(self, action: ActionRequest, context) -> PolicyDecision:
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

        denylist_decision = self.check_shell_denylist(command)
        if denylist_decision.status != DecisionStatus.ALLOWED:
            return denylist_decision

        network_decision = self.check_network_command(command)
        if network_decision.status != DecisionStatus.ALLOWED:
            return network_decision

        allowlist_decision = self.check_shell_allowlist(command)
        if allowlist_decision.status != DecisionStatus.ALLOWED:
            return allowlist_decision

        operand_decision = self.check_shell_operands(command, context)
        if operand_decision.status != DecisionStatus.ALLOWED:
            return operand_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell command allowed",
            policy="shell.allowed",
            risk_level=RiskLevel.LOW,
        )

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
        raw_decision = self.check_sensitive_path_name(Path(raw_path).name)
        if raw_decision.status != DecisionStatus.ALLOWED:
            return raw_decision

        if context is not None:
            resolved_path = (context.normalized_workspace() / raw_path).resolve()
            resolved_decision = self.check_sensitive_path_name(resolved_path.name)
            if resolved_decision.status != DecisionStatus.ALLOWED:
                return resolved_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="File is not sensitive",
            policy="filesystem.not_sensitive",
            risk_level=RiskLevel.LOW,
        )

    def check_sensitive_path_name(self, name: str) -> PolicyDecision:
        if name in self.sensitive_file_names:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=f"Sensitive file name is blocked: {name}",
                policy="filesystem.sensitive_name",
                risk_level=RiskLevel.HIGH,
            )

        for suffix in self.sensitive_file_suffixes:
            if name.endswith(suffix):
                return PolicyDecision(
                    status=DecisionStatus.BLOCKED,
                    reason="Sensitive file suffixe is blocked",
                    policy="filesystem.sensitive_suffix",
                    risk_level=RiskLevel.HIGH,
                )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="File is not sensitive",
            policy="filesystem.not_sensitive",
            risk_level=RiskLevel.LOW,
        )

    def check_shell_allowlist(self, command: str) -> PolicyDecision:
        command_name = self.get_command_name(command)

        if command_name not in self.allowed_shell_commands:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=f"Shell command is not allowed: {command_name}",
                policy="shell.command_not_allowed",
                risk_level=RiskLevel.HIGH,
            )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell command is allowed",
            policy="shell.command_allowed",
            risk_level=RiskLevel.LOW,
        )

    def check_shell_denylist(self, command: str) -> PolicyDecision:
        command_name = self.get_command_name(command)

        if command_name in self.destructive_commands:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=f"Destructive command is blocked {command_name}",
                policy="shell.destructive_command",
                risk_level=RiskLevel.HIGH,
            )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell command is not destructive",
            policy="shell.not_destructive",
            risk_level=RiskLevel.LOW,
        )

    def check_network_command(self, command: str) -> PolicyDecision:
        command_name = self.get_command_name(command)

        if command_name in self.network_commands:
            return PolicyDecision(
                status=DecisionStatus.REQUIRES_APPROVAL,
                reason=f"Network command requires approval {command_name}",
                policy="shell.network_requires_approval",
                risk_level=RiskLevel.MEDIUM,
            )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell command does not use network",
            policy="shell.no_network",
            risk_level=RiskLevel.LOW,
        )

    def check_shell_operands(self, command: str, context: RuntimeContext) -> PolicyDecision:
        try:
            parts = shlex.split(command)
        except ValueError:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason="Invalid shell command syntax",
                policy="shell.invalid_syntax",
                risk_level=RiskLevel.MEDIUM,
            )

        option_parsing_stopped = False

        for token in parts[1:]:
            if token in SHELL_CONTROL_TOKENS:
                return PolicyDecision(
                    status=DecisionStatus.BLOCKED,
                    reason="Shell control syntax is not supported",
                    policy="shell.control_syntax_unsupported",
                    risk_level=RiskLevel.HIGH,
                )

            if token == "--":
                option_parsing_stopped = True
                continue

            if token.startswith("-") and not option_parsing_stopped:
                if "/" in token or "\\" in token or "=" in token:
                    return PolicyDecision(
                        status=DecisionStatus.BLOCKED,
                        reason="Shell option syntax is not supported",
                        policy="shell.option_syntax_unsupported",
                        risk_level=RiskLevel.HIGH,
                    )

                continue

            boundary_decision = self.check_workspace_boundary(token, context)
            if boundary_decision.status != DecisionStatus.ALLOWED:
                return boundary_decision

            sensitive_decision = self.check_sensitive_file(token, context)
            if sensitive_decision.status != DecisionStatus.ALLOWED:
                return sensitive_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell operands stay inside workspace root",
            policy="shell.operands_workspace_only",
            risk_level=RiskLevel.LOW,
        )

    def get_command_name(self, command: str):
        parts = shlex.split(command)

        if not parts:
            return ""

        return parts[0]
