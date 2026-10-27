"""Read-only M0 authorization control plane for the original LightUp domain.

This view deliberately produces no execution permit. A recorded request, a
current domain grant, or an approved risk elevation is never interpreted as
independent client consent, action-time revocation proof or HUMAN GO.
"""
from __future__ import annotations

from dataclasses import dataclass

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
class ClientAuthorizationPlan:
    client_id: str
    client_name: str
    submitted_requests: int
    approved_requests: int
    rejected_requests: int
    engagements: tuple[EngagementPlan, ...]
    state: str = "PLAN_ONLY"
    execution_allowed: bool = False


def build_client_authorization_plan(
    store: DomainStore, actor: AccessContext, client_id: str
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
        grant = store.get_current_grant(actor, engagement.engagement_id)
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
    )
