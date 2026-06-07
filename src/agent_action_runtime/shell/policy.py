from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import DecisionStatus, PolicyDecision, RiskLevel
from agent_action_runtime.errors import ExecutionError
from agent_action_runtime.filesystem.sandbox import is_inside_workspace
from agent_action_runtime.filesystem.sensitivity import SensitiveFilePolicy
from agent_action_runtime.shell.parser import SHELL_CONTROL_TOKENS, parse_command


ALLOWED_SHELL_COMMANDS = ["cat", "head", "tail", "wc"]

DESTRUCTIVE_COMMANDS = [
    "rm",
]

NETWORK_COMMANDS = [
    "curl",
]


class ShellPolicy:
    def __init__(
        self,
        *,
        sensitive_files: SensitiveFilePolicy | None = None,
        allowed_shell_commands: list[str] | None = None,
        destructive_commands: list[str] | None = None,
        network_commands: list[str] | None = None,
    ) -> None:
        self.sensitive_files = sensitive_files or SensitiveFilePolicy()
        self.allowed_shell_commands = allowed_shell_commands or ALLOWED_SHELL_COMMANDS
        self.destructive_commands = destructive_commands or DESTRUCTIVE_COMMANDS
        self.network_commands = network_commands or NETWORK_COMMANDS

    def evaluate(self, command: str, context: RuntimeContext) -> PolicyDecision:
        try:
            parts = parse_command(command)
        except ExecutionError as error:
            return PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=str(error),
                policy=error.code,
                risk_level=RiskLevel.MEDIUM,
            )

        denylist_decision = self.check_denylist(parts)
        if denylist_decision.status != DecisionStatus.ALLOWED:
            return denylist_decision

        network_decision = self.check_network_command(parts)
        if network_decision.status != DecisionStatus.ALLOWED:
            return network_decision

        allowlist_decision = self.check_allowlist(parts)
        if allowlist_decision.status != DecisionStatus.ALLOWED:
            return allowlist_decision

        operand_decision = self.check_operands(parts, context)
        if operand_decision.status != DecisionStatus.ALLOWED:
            return operand_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell command allowed",
            policy="shell.allowed",
            risk_level=RiskLevel.LOW,
        )

    def check_allowlist(self, parts: list[str]) -> PolicyDecision:
        command_name = parts[0]

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

    def check_denylist(self, parts: list[str]) -> PolicyDecision:
        command_name = parts[0]

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

    def check_network_command(self, parts: list[str]) -> PolicyDecision:
        command_name = parts[0]

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

    def check_operands(self, parts: list[str], context: RuntimeContext) -> PolicyDecision:
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

            sensitive_decision = self.sensitive_files.check_file(token, context)
            if sensitive_decision.status != DecisionStatus.ALLOWED:
                return sensitive_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="Shell operands stay inside workspace root",
            policy="shell.operands_workspace_only",
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
