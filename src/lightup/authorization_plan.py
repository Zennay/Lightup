"""Read-only M0 authorization control plane for the original LightUp domain.

This view deliberately produces no execution permit. A recorded request, a
current domain grant, or an approved risk elevation is never interpreted as
independent client consent, action-time revocation proof or HUMAN GO.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .domain import AccessContext, ApprovalStatus, DomainStore, RequestStatus
from .engagements import RiskLevel


@dataclass(frozen=True)
class EngagementPlan:
    engagement_id: str
    name: str
    status: str
    recorded_scope: tuple[str, ...]
    excluded_scope: tuple[str, ...]
    max_risk: RiskLevel | None
    pending_elevations: int
    blockers: tuple[str, ...]
    decision: str = "HOLD"
    execution_allowed: bool = False


@dataclass(frozen=True)
class AssessmentRequestPlan:
    """A tenant-scoped review record, never an engagement grant or permit."""

    request_id: str
    status: str
    requested_assets: tuple[str, ...]
    requested_mode: str
    requested_risk: RiskLevel
    submitted_at: str
    reviewed_at: str | None
    engagement_authority_inferred: bool = False
    execution_allowed: bool = False


@dataclass(frozen=True)
class ClientAuthorizationPlan:
    client_id: str
    client_name: str
    submitted_requests: int
    approved_requests: int
    rejected_requests: int
    engagements: tuple[EngagementPlan, ...]
    evaluated_at: str
    request_reviews: tuple[AssessmentRequestPlan, ...] = ()
    state: str = "PLAN_ONLY"
    execution_allowed: bool = False


def build_client_authorization_plan(
    store: DomainStore, actor: AccessContext, client_id: str,
    evaluation_time: datetime | None = None,
) -> ClientAuthorizationPlan:
    """Summarize original records without writing a grant or enabling a handler.

    Assessment requests belong to a client, not an engagement. Do not infer
    that a merely approved client request authorizes any particular
    engagement: only the original domain's request-bound grant lookup can
    report an existing current grant. Even then the plan remains HOLD.
    """
    # Clients may read only their own tenant; operators name a tenant. The
    # original domain repeats this boundary on every underlying read.
    actor.resolve_client(client_id, "build_client_authorization_plan")
    instant = datetime.now(timezone.utc) if evaluation_time is None else evaluation_time
    if (type(instant) is not datetime or instant.tzinfo is None
            or instant.utcoffset() is None):
        raise ValueError("plan evaluation requires an exact aware datetime")
    instant = instant.astimezone(timezone.utc)
    client = store.get_client(actor, client_id)
    requests = store.list_assessment_requests(actor, client_id)
    engagements = store.list_engagements(actor, client_id)
    all_pending = store.list_risk_approvals(actor)
    pending_by_engagement: dict[str, int] = {}
    for approval in all_pending:
        if approval.client_id == client_id and approval.status is ApprovalStatus.PENDING:
            pending_by_engagement[approval.engagement_id] = (
                pending_by_engagement.get(approval.engagement_id, 0) + 1
            )

    rows = []
    for engagement in engagements:
        # The original domain excludes unbound, expired or otherwise
        # non-current grants. This read is not an approval or consent check.
        grant = store.get_current_grant(actor, engagement.engagement_id, now=instant)
        pending_count = pending_by_engagement.get(engagement.engagement_id, 0)
        blockers = []
        if grant is None:
            blockers.append("No current request-bound recorded scope grant.")
        if pending_count:
            blockers.append("Pending risk-elevation decision.")
        blockers.extend((
            "Independent client consent and at-use revocation not verified.",
            "Security/source-owner review and explicit HUMAN GO not recorded here.",
            "M0 active target execution is disabled.",
        ))
        rows.append(EngagementPlan(
            engagement_id=engagement.engagement_id,
            name=engagement.name,
            status=engagement.status.value,
            recorded_scope=tuple(grant.scope.assets) if grant else (),
            excluded_scope=tuple(grant.scope.excluded_assets) if grant else (),
            max_risk=grant.scope.max_risk if grant else None,
            pending_elevations=pending_count,
            blockers=tuple(blockers),
        ))

    return ClientAuthorizationPlan(
        client_id=client_id,
        client_name=client.name,
        submitted_requests=sum(
            request.status in (RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW)
            for request in requests
        ),
        approved_requests=sum(request.status is RequestStatus.APPROVED for request in requests),
        rejected_requests=sum(request.status is RequestStatus.REJECTED for request in requests),
        engagements=tuple(rows),
        evaluated_at=instant.isoformat(),
        request_reviews=tuple(
            AssessmentRequestPlan(
                request_id=request.request_id,
                status=request.status.value,
                requested_assets=tuple(request.requested_assets),
                requested_mode=request.requested_mode.value,
                requested_risk=request.requested_risk,
                submitted_at=request.created_at,
                reviewed_at=request.decided_at,
            )
            for request in requests
        ),
    )


def to_review_payload(plan: ClientAuthorizationPlan) -> dict:
    """Build a deterministic, non-authorizing HUMAN review document.

    Even a current request-bound recorded grant cannot make any decision
    executable. The payload contains no signed consent, token, or capability
    invocation; it must never be accepted as a grant or activation permit.
    """
    if (type(plan) is not ClientAuthorizationPlan
            or plan.state != "PLAN_ONLY" or plan.execution_allowed is not False):
        raise ValueError("authorization plan is not fail-closed")
    rows = []
    for entry in plan.engagements:
        if (type(entry) is not EngagementPlan or entry.decision != "HOLD"
                or entry.execution_allowed is not False
                or (entry.max_risk is not None and type(entry.max_risk) is not RiskLevel)):
            raise ValueError("engagement is not fail-closed")
        rows.append({
            "engagement_id": entry.engagement_id,
            "name": entry.name,
            "status": entry.status,
            "recorded_scope": sorted(entry.recorded_scope),
            "excluded_scope": sorted(entry.excluded_scope),
            "recorded_risk_ceiling": int(entry.max_risk) if entry.max_risk is not None else None,
            "pending_elevations": entry.pending_elevations,
            "blockers": list(entry.blockers),
            "decision": "HOLD",
            "execution_allowed": False,
        })
    request_rows = []
    for request in plan.request_reviews:
        if (type(request) is not AssessmentRequestPlan
                or request.engagement_authority_inferred is not False
                or request.execution_allowed is not False
                or type(request.requested_risk) is not RiskLevel
                or request.status not in {status.value for status in RequestStatus}):
            raise ValueError("assessment request is not fail-closed")
        request_rows.append({
            "request_id": request.request_id,
            "status": request.status,
            "requested_assets": sorted(request.requested_assets),
            "requested_mode": request.requested_mode,
            "requested_risk": int(request.requested_risk),
            "submitted_at": request.submitted_at,
            "reviewed_at": request.reviewed_at,
            "engagement_authority_inferred": False,
            "execution_allowed": False,
        })
    return {
        "format": "lightup-plan-only-review-v1",
        "evaluated_at": plan.evaluated_at,
        "client": {"id": plan.client_id, "name": plan.client_name},
        "requests": {
            "awaiting_review": plan.submitted_requests,
            "approved": plan.approved_requests,
            "rejected": plan.rejected_requests,
            "engagement_binding_inferred": False,
        },
        "engagements": sorted(rows, key=lambda row: row["engagement_id"]),
        "request_review": sorted(request_rows, key=lambda row: row["request_id"]),
        "authority": {
            "execution_allowed": False,
            "capability_dispatch_allowed": False,
            "client_consent_verified": False,
            "revocation_at_use_verified": False,
            "human_go_verified": False,
        },
        "state": "PLAN_ONLY",
        "disclaimer": "Unsigned private HUMAN review only; not a grant, consent, scan or release.",
    }
