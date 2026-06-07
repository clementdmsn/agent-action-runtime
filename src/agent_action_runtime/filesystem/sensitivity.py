from pathlib import Path

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import DecisionStatus, PolicyDecision, RiskLevel


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


class SensitiveFilePolicy:
    def __init__(
        self,
        *,
        sensitive_file_names: list[str] | None = None,
        sensitive_file_suffixes: list[str] | None = None,
    ) -> None:
        self.sensitive_file_names = sensitive_file_names or SENSITIVE_FILE_NAMES
        self.sensitive_file_suffixes = sensitive_file_suffixes or SENSITIVE_FILE_SUFFIXES

    def check_file(self, raw_path: str, context: RuntimeContext | None = None) -> PolicyDecision:
        raw_decision = self.check_path_name(Path(raw_path).name)
        if raw_decision.status != DecisionStatus.ALLOWED:
            return raw_decision

        if context is not None:
            resolved_path = (context.normalized_workspace() / raw_path).resolve()
            resolved_decision = self.check_path_name(resolved_path.name)
            if resolved_decision.status != DecisionStatus.ALLOWED:
                return resolved_decision

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="File is not sensitive",
            policy="filesystem.not_sensitive",
            risk_level=RiskLevel.LOW,
        )

    def check_path_name(self, name: str) -> PolicyDecision:
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
                    reason="Sensitive file suffix is blocked",
                    policy="filesystem.sensitive_suffix",
                    risk_level=RiskLevel.HIGH,
                )

        return PolicyDecision(
            status=DecisionStatus.ALLOWED,
            reason="File is not sensitive",
            policy="filesystem.not_sensitive",
            risk_level=RiskLevel.LOW,
        )
