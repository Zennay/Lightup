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
    recorded_capabilities: tuple[str, ...] = ()
    unrestricted_capabilities_recorded: bool = False
    grant_valid_from: str | None = None
    grant_valid_until: str | None = None
    scope_record_state: str = "NOT_RECORDED"
    last_eligible_grant_expired_at: str | None = None
    next_eligible_grant_valid_from: str | None = None
    risk_elevation_reviews: tuple[RiskElevationReviewPlan, ...] = ()
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
class RiskElevationReviewPlan:
    """A recorded risk decision, never a grant, consent or execution permit."""

    approval_id: str
    status: str
    requested_risk: RiskLevel
    requested_at: str
    reviewed_at: str | None
    authority_inferred: bool = False
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
    reviews_by_engagement: dict[str, list[RiskElevationReviewPlan]] = {}
    for approval in all_pending:
        if approval.client_id != client_id:
            continue
        reviews_by_engagement.setdefault(approval.engagement_id, []).append(
            RiskElevationReviewPlan(
                approval_id=approval.approval_id,
                status=approval.status.value,
                requested_risk=approval.requested_risk,
                requested_at=approval.created_at,
                reviewed_at=approval.decided_at,
            )
        )
        if approval.status is ApprovalStatus.PENDING:
            pending_by_engagement[approval.engagement_id] = (
                pending_by_engagement.get(approval.engagement_id, 0) + 1
            )

    rows = []
    for engagement in engagements:
        # The original domain excludes unbound, expired or otherwise
        # non-current grants. This read is not an approval or consent check.
        grant = store.get_current_grant(actor, engagement.engagement_id, now=instant)
        # Read the original domain's provenance-filtered history only. Legacy
        # unbound or incompatible grants are never reconstructed as scope.
        eligible_history = (
            store.list_authorization_grants(actor, engagement.engagement_id)
            if grant is None else ()
        )
        expired = [
            item.valid_until for item in eligible_history
            if item.valid_until < instant
        ]
        upcoming = [
            item.valid_from for item in eligible_history
            if item.valid_from > instant
        ]
        last_expiry = max(expired) if expired else None
        next_start = min(upcoming) if upcoming else None
        scope_record_state = (
            "CURRENT" if grant is not None else
            "NOT_YET_VALID" if next_start is not None else
            "EXPIRED" if last_expiry is not None else "NOT_RECORDED"
        )
        pending_count = pending_by_engagement.get(engagement.engagement_id, 0)
        blockers = []
        if scope_record_state == "EXPIRED":
            blockers.append(
                "The last eligible request-bound scope grant has expired; "
                "a new explicit grant and independent consent review are required."
            )
        elif scope_record_state == "NOT_YET_VALID":
            blockers.append(
                "A recorded request-bound scope grant is not yet valid; "
                "it cannot be treated as current authorization."
            )
        elif grant is None:
            blockers.append("No current request-bound recorded scope grant.")
        if pending_count:
            blockers.append("Pending risk-elevation decision.")
        if grant is not None and not grant.scope.allowed_capabilities:
            blockers.append(
                "Recorded grant has unrestricted capabilities; replace with "
                "an explicit least-privilege capability list."
            )
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
            recorded_capabilities=tuple(grant.scope.allowed_capabilities) if grant else (),
            unrestricted_capabilities_recorded=(
                grant is not None and not grant.scope.allowed_capabilities
            ),
            grant_valid_from=grant.valid_from.isoformat() if grant else None,
            grant_valid_until=grant.valid_until.isoformat() if grant else None,
            scope_record_state=scope_record_state,
            last_eligible_grant_expired_at=(
                last_expiry.isoformat() if last_expiry else None
            ),
            next_eligible_grant_valid_from=(
                next_start.isoformat() if next_start else None
            ),
            risk_elevation_reviews=tuple(sorted(
                reviews_by_engagement.get(engagement.engagement_id, ()),
                key=lambda review: review.approval_id,
            )),
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
                or (entry.max_risk is not None and type(entry.max_risk) is not RiskLevel)
                or type(entry.unrestricted_capabilities_recorded) is not bool
                or entry.scope_record_state not in {
                    "CURRENT", "EXPIRED", "NOT_YET_VALID", "NOT_RECORDED"
                }
                or (entry.scope_record_state == "CURRENT") != (entry.max_risk is not None)):

            raise ValueError("engagement is not fail-closed")
        risk_reviews = []
        for review in entry.risk_elevation_reviews:
            if (type(review) is not RiskElevationReviewPlan
                    or type(review.requested_risk) is not RiskLevel
                    or review.status not in {status.value for status in ApprovalStatus}
                    or review.authority_inferred is not False
                    or review.execution_allowed is not False):
                raise ValueError("risk elevation review is not fail-closed")
            risk_reviews.append({
                "approval_id": review.approval_id,
                "status": review.status,
                "requested_risk": int(review.requested_risk),
                "requested_at": review.requested_at,
                "reviewed_at": review.reviewed_at,
                "grant_inferred": False,
                "execution_allowed": False,
            })
        rows.append({
            "engagement_id": entry.engagement_id,
            "name": entry.name,
            "status": entry.status,
            "recorded_scope": sorted(entry.recorded_scope),
            "excluded_scope": sorted(entry.excluded_scope),
            "recorded_risk_ceiling": int(entry.max_risk) if entry.max_risk is not None else None,
            "recorded_capabilities": sorted(entry.recorded_capabilities),
            "unrestricted_capabilities_recorded": entry.unrestricted_capabilities_recorded,
            "grant_valid_from": entry.grant_valid_from,
            "grant_valid_until": entry.grant_valid_until,
            "scope_record_state": entry.scope_record_state,
            "last_eligible_grant_expired_at": entry.last_eligible_grant_expired_at,
            "next_eligible_grant_valid_from": entry.next_eligible_grant_valid_from,
            "pending_elevations": entry.pending_elevations,
            "risk_elevation_review": risk_reviews,
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


def build_operator_portfolio_review_payload(
    store: DomainStore, actor: AccessContext,
    evaluation_time: datetime | None = None,
) -> dict:
    """Operator-only, aggregate M0 status without issuing tenant authority.

    Every per-tenant scope lookup shares one exact observation time. This
    artifact is private and unsigned, and is never an execution input.
    """
    actor.require_operator("build_operator_portfolio_review_payload")
    instant = datetime.now(timezone.utc) if evaluation_time is None else evaluation_time
    if (type(instant) is not datetime or instant.tzinfo is None
            or instant.utcoffset() is None):
        raise ValueError("portfolio review requires an exact aware datetime")
    instant = instant.astimezone(timezone.utc)
    tenants = []
    review_details = []
    for tenant in store.list_clients(actor):
        plan = build_client_authorization_plan(
            store, actor, tenant.client_id, evaluation_time=instant
        )
        # Identifiers, not assets or consent material. These are private,
        # human-only pointers back to the original persisted domain records.
        for request in plan.request_reviews:
            if request.status in {
                RequestStatus.SUBMITTED.value, RequestStatus.UNDER_REVIEW.value,
            }:
                review_details.append({
                    "client_id": plan.client_id,
                    "client_name": plan.client_name,
                    "kind": "review_client_requests",
                    "record_type": "request",
                    "record_id": request.request_id,
                    "created_at": request.submitted_at,
                    "decision": "HOLD",
                    "execution_allowed": False,
                })
        for entry in plan.engagements:
            for review in entry.risk_elevation_reviews:
                if review.status == ApprovalStatus.PENDING.value:
                    review_details.append({
                        "client_id": plan.client_id,
                        "client_name": plan.client_name,
                        "kind": "review_risk_decisions",
                        "record_type": "risk_elevation",
                        "record_id": review.approval_id,
                        "created_at": review.requested_at,
                        "decision": "HOLD",
                        "execution_allowed": False,
                    })
            kinds = []
            if entry.unrestricted_capabilities_recorded:
                kinds.append("review_unrestricted_grants")
            if entry.scope_record_state == "EXPIRED":
                kinds.append("review_expired_grants")
            elif entry.scope_record_state == "NOT_YET_VALID":
                kinds.append("review_future_grants")
            elif entry.scope_record_state == "NOT_RECORDED":
                kinds.append("review_missing_grants")
            for kind in kinds:
                review_details.append({
                    "client_id": plan.client_id,
                    "client_name": plan.client_name,
                    "kind": kind,
                    "record_type": "engagement",
                    "record_id": entry.engagement_id,
                    "created_at": None,
                    "decision": "HOLD",
                    "execution_allowed": False,
                })
        tenants.append({
            "client_id": plan.client_id,
            "client_name": plan.client_name,
            "requests_awaiting_review": plan.submitted_requests,
            "requests_approved": plan.approved_requests,
            "requests_rejected": plan.rejected_requests,
            "pending_risk_decisions": sum(
                entry.pending_elevations for entry in plan.engagements
            ),
            "engagements_hold": len(plan.engagements),
            "without_current_grant": sum(
                entry.max_risk is None for entry in plan.engagements
            ),
            "expired_grant_engagements": sum(
                entry.scope_record_state == "EXPIRED"
                for entry in plan.engagements
            ),
            "future_dated_grant_engagements": sum(
                entry.scope_record_state == "NOT_YET_VALID"
                for entry in plan.engagements
            ),
            "unrestricted_legacy_scopes": sum(
                entry.unrestricted_capabilities_recorded
                for entry in plan.engagements
            ),
            "decision": "HOLD",
            "execution_allowed": False,
        })
    # A review queue, not an authorization workflow. A count represents
    # separate review items, not an independent consent or execution decision.
    review_queue = []
    for tenant in tenants:
        not_recorded = max(
            0, tenant["without_current_grant"]
            - tenant["expired_grant_engagements"]
            - tenant["future_dated_grant_engagements"]
        )
        review_kinds = (
            ("review_client_requests", tenant["requests_awaiting_review"]),
            ("review_risk_decisions", tenant["pending_risk_decisions"]),
            ("review_unrestricted_grants", tenant["unrestricted_legacy_scopes"]),
            ("review_expired_grants", tenant["expired_grant_engagements"]),
            ("review_future_grants", tenant["future_dated_grant_engagements"]),
            ("review_missing_grants", not_recorded),
        )
        actions = [
            {
                "kind": kind,
                "count": count,
                "review_only": True,
                "execution_allowed": False,
            }
            for kind, count in review_kinds if count > 0
        ]
        if actions:
            review_queue.append({
                "client_id": tenant["client_id"],
                "client_name": tenant["client_name"],
                "review_items": sum(action["count"] for action in actions),
                "actions": actions,
                "decision": "HOLD",
                "execution_allowed": False,
            })
    review_queue.sort(
        key=lambda item: (-item["review_items"], item["client_id"])
    )
    # Every summary count must reconcile with exactly that many private
    # original-record pointers. Never show an optimistic incomplete queue.
    expected = {
        (item["client_id"], action["kind"]): action["count"]
        for item in review_queue for action in item["actions"]
    }
    observed = {}
    for item in review_details:
        key = (item["client_id"], item["kind"])
        observed[key] = observed.get(key, 0) + 1
    if expected != observed:
        raise ValueError("operator review summary does not match source records")
    review_details.sort(
        key=lambda item: (
            item["kind"], item["client_id"], item["created_at"] or "",
            item["record_id"],
        )
    )
    return {
        "format": "lightup-m0-portfolio-review-v1",
        "evaluated_at": instant.isoformat(),
        "tenants": sorted(tenants, key=lambda tenant: tenant["client_id"]),
        "review_queue": review_queue,
        "review_details": review_details,
        "authority": {
            "execution_allowed": False,
            "capability_dispatch_allowed": False,
            "client_consent_verified": False,
            "revocation_at_use_verified": False,
            "human_go_verified": False,
        },
        "state": "PLAN_ONLY",
        "disclaimer": "Private unsigned HUMAN summary; not a grant, consent or activation.",
    }


def to_operator_review_worklist_csv(
    portfolio: dict, kind: str | None = None, *, records: bool = False,
) -> str:
    """Export private HUMAN-review totals or exact-record work items.

    Both forms deliberately exclude assets, consent receipts, scope tokens and
    execution parameters. The operator route authenticates before building it;
    either CSV is a HUMAN-only planning document, never execution authority.
    """
    import csv
    import io

    if (type(portfolio) is not dict
            or portfolio.get("format") != "lightup-m0-portfolio-review-v1"
            or portfolio.get("state") != "PLAN_ONLY"
            or portfolio.get("authority", {}).get("execution_allowed") is not False
            or portfolio.get("authority", {}).get("human_go_verified") is not False):
        raise ValueError("portfolio is not a fail-closed review document")

    allowed_kinds = {
        "review_client_requests", "review_risk_decisions",
        "review_unrestricted_grants", "review_expired_grants",
        "review_future_grants", "review_missing_grants",
    }
    if kind is not None and kind not in allowed_kinds:
        raise ValueError("unknown HUMAN worklist category")
    if type(records) is not bool:
        raise ValueError("record-level export must be an explicit boolean")

    def cell(value: object) -> str:
        raw = str(value)
        # Spreadsheet formula injection must not turn a tenant's display name
        # into a command when an operator opens a private CSV in Excel/Sheets.
        trimmed = raw.lstrip(" \t\r\n\uFEFF")
        if (trimmed.startswith(("=", "+", "-", "@"))
                or (raw and (ord(raw[0]) < 32 or raw[0] == "\uFEFF"))):
            return "'" + raw
        return raw

    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    if records:
        writer.writerow((
            "evaluated_at_utc", "client_id", "client_name", "review_category",
            "record_type", "record_id", "submitted_or_requested_at_utc",
            "review_state", "authority_state", "execution_allowed",
        ))
        record_types = {
            "review_client_requests": "request",
            "review_risk_decisions": "risk_elevation",
            "review_unrestricted_grants": "engagement",
            "review_expired_grants": "engagement",
            "review_future_grants": "engagement",
            "review_missing_grants": "engagement",
        }
        for item in portfolio["review_details"]:
            if (item["kind"] not in allowed_kinds
                    or item["record_type"] != record_types[item["kind"]]
                    or type(item["record_id"]) is not str
                    or not item["record_id"]
                    or item["decision"] != "HOLD"
                    or item["execution_allowed"] is not False):
                raise ValueError("source record is not a fail-closed HUMAN work item")
            if kind is not None and item["kind"] != kind:
                continue
            writer.writerow(tuple(map(cell, (
                portfolio["evaluated_at"], item["client_id"],
                item["client_name"], item["kind"], item["record_type"],
                item["record_id"], item["created_at"] or "",
                "HUMAN_REVIEW_ONLY", "HOLD_PLAN_ONLY", "FALSE",
            ))))
        return output.getvalue()
    writer.writerow((
        "evaluated_at_utc", "client_id", "client_name", "review_category",
        "pending_items", "review_state", "authority_state", "execution_allowed",
    ))
    for tenant in portfolio["review_queue"]:
        if (tenant["decision"] != "HOLD"
                or tenant["execution_allowed"] is not False):
            raise ValueError("review queue is not fail-closed")
        for action in tenant["actions"]:
            if kind is not None and action["kind"] != kind:
                continue
            if (action["review_only"] is not True
                    or action["execution_allowed"] is not False
                    or type(action["count"]) is not int
                    or action["count"] < 1):
                raise ValueError("review action is not fail-closed")
            writer.writerow(tuple(map(cell, (
                portfolio["evaluated_at"], tenant["client_id"],
                tenant["client_name"], action["kind"], action["count"],
                "HUMAN_REVIEW_ONLY", "HOLD_PLAN_ONLY", "FALSE",
            ))))
    return output.getvalue()
