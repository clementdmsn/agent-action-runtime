from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import ActionRequest, ActionResult, TraceEvent


class TraceWriter:
    def write(self, action: ActionRequest, result: ActionResult, context: RuntimeContext) -> None:
        trace_path = getattr(context, "trace_path", None)

        if trace_path is None:
            return

        path = Path(trace_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        event = TraceEvent.from_action_result(
            action,
            result,
            timestamp=datetime.now(timezone.utc),
        )

        with path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event.model_dump(mode="json"), ensure_ascii=False))
            file.write("\n")
