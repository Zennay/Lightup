"""Additional request-bound STOP veto for the canonical LightUp ToolExecutor.

This is an opt-in composition factory, not an active default / release. A
caller still needs all original domain, scope, consent and tool gates. This
module does not issue authority and does not contact a target by itself.
"""
from __future__ import annotations

from .ai.orchestration import (RunContext, ToolCall, ToolExecutor, ToolRegistry,\n                               ToolResult, ToolDenied)
from .engagements import AuthorizationGrant
from .execution_policy import (
    ExecutionPolicy,
    ExecutionRequest,
    InteractionKind,
    PolicyDecision,
)
from .revocation_stop import _literal, deny_only_stop_state
from .state import StateStore


class StopAwareExecutionPolicy:
    """Fail-closed adapter preserving the unchanged original ExecutionPolicy.

    A policy decision is a pre-handler veto, NOT atomic distributed revocation.
    A STOP written between the final observation and handler startup will not
    magically interrupt that handler. Original runtime owners must close this
    race in the real dispatch lifecycle before operational release.
    """

    def __init__(self, *, database: str, run_context: RunContext):
        if type(database) is not str or not database or type(run_context) is not RunContext:
            raise ValueError("a canonical original run and database are required")
        self._database = database
        self._context = run_context
        self._original = ExecutionPolicy()
        self._client_id = _literal(run_context.client_id, "client identity")
        self._engagement_id = _literal(run_context.engagement_id, "engagement identity")

    def _request_bound(self, request: object) -> bool:
        if type(request) is not ExecutionRequest:
            return False
        ctx = self._context
        # TARGET_ACTIVE is especially sensitive to mismatched in-memory grant
        # lineage: the stop ledger must bind the same real engagement + tenant.
        if request.authorization is not ctx.authorization:
            return False
        grant = request.authorization
        if grant is not None:
            if type(grant) is not AuthorizationGrant:
                return False
            if (type(grant.client_id) is not str or grant.client_id != self._client_id
                    or type(grant.engagement_id) is not str
                    or grant.engagement_id != self._engagement_id):
                return False
        if request.interaction is InteractionKind.TARGET_ACTIVE and grant is None:
            return False
        return True

    def decide(self, request: ExecutionRequest) -> PolicyDecision:
        # This is extra denial only. Never call original policy on a request
        # with mismatched engagement/grant provenance.
        if not self._request_bound(request):
            return PolicyDecision(False, "STOP guard source identity mismatch")
        first = deny_only_stop_state(
            self._database, engagement_id=self._engagement_id,
            client_id=self._client_id,
        )
        if first["status"] != "NO_STOP_RECORDED":
            return PolicyDecision(False, "STOP/HOLD admission")
        original_decision = self._original.decide(request)
        if type(original_decision) is not PolicyDecision or original_decision.allowed is not True:
            return PolicyDecision(False, "original execution policy denied")
        # Tighten the *local* check/read interval without pretending this is a
        # transaction spanning the subsequent handler / external worker.
        final = deny_only_stop_state(
            self._database, engagement_id=self._engagement_id,
            client_id=self._client_id,
        )
        if final["status"] != "NO_STOP_RECORDED":
            return PolicyDecision(False, "STOP/HOLD changed during decision")
        return original_decision


class StopAwareToolExecutor:
    """Source-bound adapter that rejects a substituted RunContext before tools."""

    def __init__(self, *, database: str, run_context: RunContext,
                 registry: ToolRegistry, state: StateStore):
        if type(run_context) is not RunContext or type(registry) is not ToolRegistry:
            raise ValueError("canonical original context and registry required")
        if state is None:
            raise ValueError("original StateStore required")
        self._run_context = run_context
        self._executor = ToolExecutor(
            registry, state,
            policy=StopAwareExecutionPolicy(
                database=database, run_context=run_context,
            ),
        )

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
        if context is not self._run_context:
            raise ToolDenied("STOP guard cannot accept substituted run context")
        # Original ToolExecutor retains all existing mode, risk, registry,
        # evidence and policy admission. We only add source-bound denial.
        return self._executor.execute(context, call)


def create_stop_aware_executor(*, database: str, run_context: RunContext,
                               registry: ToolRegistry,
                               state: StateStore) -> StopAwareToolExecutor:
    """Explicit opt-in composition; no standard entrypoint is modified."""
    return StopAwareToolExecutor(
        database=database, run_context=run_context,
        registry=registry, state=state,
    )
