from __future__ import annotations

import json
from pathlib import Path

import typer

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import ActionRequest, ResultStatus
from agent_action_runtime.replay import replay_trace
from agent_action_runtime.runtime import ActionRuntime

app = typer.Typer()


class CLIApp:
    def __init__(self) -> None:
        self.runtime = ActionRuntime()

    def run(
        self,
        action_file: Path,
        workspace: Path,
        trace: Path | None,
        policy_profile: str,
        json_output: bool,
    ) -> None:
        raw = json.loads(action_file.read_text(encoding="utf-8"))
        action = ActionRequest.model_validate(raw)

        context = RuntimeContext(
            workspace_root=workspace or Path("examples/workspace"),
            trace_path=trace,
            policy_profile=policy_profile,
        )

        result = self.runtime.run(action, context)
        self.print_result(result, json_output)
        raise typer.Exit(result_exit_code(result.status))

    def print_result(self, result, json_output: bool) -> None:
        if json_output:
            typer.echo(result.model_dump_json(indent=2))
            return

        if result.observation is not None:
            typer.echo(f"{result.status}: {result.observation.summary}")
            return

        typer.echo(f"{result.status}: {result.error}")


@app.command()
def run(
    action_file: Path,
    workspace: Path | None = typer.Option(None, "--workspace", "-w"),
    trace: Path | None = typer.Option(None, "--trace", "-t"),
    policy_profile: str = typer.Option("default", "--policy-profile", "-p"),
    json_output: bool = False,
):
    cli.run(action_file, workspace, trace, policy_profile, json_output)


@app.command()
def replay(
    trace_path: Path,
    workspace: Path | None = typer.Option(None, "--workspace", "-w"),
    policy_profile: str = typer.Option("default", "--policy-profile", "-p"),
    json_output: bool = False,
):
    context = RuntimeContext(
        workspace_root=workspace or Path("examples/workspace"),
        policy_profile=policy_profile,
    )
    result = replay_trace(trace_path, context)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "events_replayed": result.events_replayed,
                    "matched": result.matched,
                    "mismatches": [
                        {
                            "event_id": mismatch.event_id,
                            "run_id": mismatch.run_id,
                            "field": mismatch.field,
                            "expected": mismatch.expected,
                            "actual": mismatch.actual,
                            "reason": mismatch.reason,
                        }
                        for mismatch in result.mismatches
                    ],
                },
                indent=2,
            )
        )
        raise typer.Exit(1 if result.has_mismatches else 0)

    typer.echo(
        f"replayed={result.events_replayed} matched={result.matched} "
        f"mismatches={len(result.mismatches)}"
    )

    raise typer.Exit(1 if result.has_mismatches else 0)


def result_exit_code(status: ResultStatus) -> int:
    if status == ResultStatus.OK:
        return 0
    if status == ResultStatus.ERROR:
        return 1
    if status == ResultStatus.BLOCKED:
        return 2
    if status == ResultStatus.REQUIRES_APPROVAL:
        return 3

    return 1


cli = CLIApp()

if __name__ == "__main__":
    app()
