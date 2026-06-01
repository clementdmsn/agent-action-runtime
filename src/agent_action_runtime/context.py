from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeLimits:
    shell_timeout_seconds: int = 3
    max_output_chars: int = 4_000
    max_file_size_bytes: int = 1_000_000
    max_write_chars: int = 100_000


@dataclass(frozen=True)
class RuntimeContext:
    workspace_root: Path = Path("examples/workspace")
    trace_path: Path | None = None
    approval_mode: bool = False
    policy_profile: str = "default"
    limits: RuntimeLimits = RuntimeLimits()

    def normalized_workspace(self) -> Path:
        return self.workspace_root.resolve()


@dataclass(frozen=True)
class ShellObservation:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    truncated: bool = False


@dataclass(frozen=True)
class ReplayMismatch:
    event_id: str
    run_id: str
    field: str
    expected: str
    actual: str
    reason: str


@dataclass(frozen=True)
class ReplayResult:
    events_replayed: int
    matched: int
    mismatches: list[ReplayMismatch]

    @property
    def has_mismatches(self) -> bool:
        return len(self.mismatches) > 0
