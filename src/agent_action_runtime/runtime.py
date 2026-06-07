from __future__ import annotations

from agent_action_runtime.context import RuntimeContext
from agent_action_runtime.contracts import (
    ActionRequest,
    ActionResult,
    DecisionStatus,
    PolicyDecision,
    RiskLevel,
)
from agent_action_runtime.errors import AgentActionRuntimeError, ExecutionError
from agent_action_runtime.executors import ActionExecutor
from agent_action_runtime.policy import PolicyEngine
from agent_action_runtime.tracing import TraceWriter
from agent_action_runtime.validation import PreparedAction, prepare_action


class ActionRuntime:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        executor: ActionExecutor | None = None,
        trace_writer: TraceWriter | None = None,
    ) -> None:
        self.policy_engine = policy_engine or PolicyEngine()
        self.executor = executor or ActionExecutor()
        self.trace_writer = trace_writer or TraceWriter()

    def run(self, action: ActionRequest, context: RuntimeContext) -> ActionResult:
        prepared = self.prepare(action)
        if isinstance(prepared, ActionResult):
            self.trace_writer.write(action, prepared, context)
            return prepared

        decision = self.evaluate_policy(prepared, context)

        if decision.status == DecisionStatus.BLOCKED:
            result = self.handle_blocked(prepared, decision)
            self.write_trace(prepared, result, context)
            return result

        if decision.status == DecisionStatus.REQUIRES_APPROVAL:
            result = self.handle_requires_approval(prepared, decision)
            self.write_trace(prepared, result, context)
            return result

        result = self.execute_allowed_action(prepared, decision, context)
        self.write_trace(prepared, result, context)
        return result

    def prepare(self, action: ActionRequest) -> PreparedAction | ActionResult:
        try:
            return prepare_action(action)
        except ExecutionError as error:
            decision = PolicyDecision(
                status=DecisionStatus.BLOCKED,
                reason=str(error),
                policy=error.code,
                risk_level=RiskLevel.LOW,
            )
            return ActionResult.blocked(decision)

    def evaluate_policy(self, action: PreparedAction, context: RuntimeContext) -> PolicyDecision:
        return self.policy_engine.evaluate(action.request, context)

    def execute_allowed_action(
        self,
        action: PreparedAction,
        decision: PolicyDecision,
        context: RuntimeContext,
    ) -> ActionResult:
        try:
            observation = self.executor.execute(action, context)
            return ActionResult.ok(decision, observation)

        except ExecutionError as error:
            return self.handle_error(action, decision, error)

        except AgentActionRuntimeError as error:
            runtime_error = ExecutionError(
                str(error),
                code=error.code,
                details={
                    "error": str(error),
                    "error_type": type(error).__name__,
                },
            )
            return self.handle_error(action, decision, runtime_error)

    def handle_blocked(self, action: PreparedAction, decision: PolicyDecision) -> ActionResult:
        return ActionResult.blocked(decision)

    def handle_requires_approval(
        self, action: PreparedAction, decision: PolicyDecision
    ) -> ActionResult:
        return ActionResult.requires_approval(decision)

    def handle_error(
        self, action: PreparedAction, decision: PolicyDecision, error: AgentActionRuntimeError
    ) -> ActionResult:
        return ActionResult.failed(
            decision,
            str(error),
            error_code=error.code,
            error_details=error.details,
        )

    def write_trace(
        self, action: PreparedAction, result: ActionResult, context: RuntimeContext
    ) -> None:
        self.trace_writer.write(action.request, result, context)
