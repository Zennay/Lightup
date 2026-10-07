"""Read-only tenant selection for the offline finding summary exporter."""
from __future__ import annotations

from .domain import AccessContext, DomainStore, FindingRecord, Role, TenantIsolationError
from .finding_export import render_findings_csv
from .models import Finding


def _identity(value: object, name: str) -> str:
    if type(value) is not str or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be canonical non-empty text")
    return value


def render_client_findings_csv(
    store: DomainStore,
    ctx: AccessContext,
    client_id: str,
    *,
    engagement_id: str | None = None,
) -> str:
    """Read and export one tenant only; ctx must come from authentication.

    This service neither authenticates a caller nor creates an AccessContext.
    It performs no writes or network calls and creates no security verdict.
    """
    if type(store) is not DomainStore or type(ctx) is not AccessContext:
        raise ValueError("canonical store and authenticated access context required")
    if type(ctx.role) is not Role:
        raise ValueError("canonical access role required")
    _identity(ctx.user_id, "user_id")
    if ctx.role is not Role.OPERATOR:
        _identity(ctx.client_id, "context client_id")
    requested = _identity(client_id, "client_id")
    scoped = ctx.resolve_client(requested, "export_findings")
    if scoped != requested:
        raise TenantIsolationError("export client selection is inconsistent")
    client = store.get_client(ctx, scoped)
    if client.client_id != scoped:
        raise TenantIsolationError("export client ownership is inconsistent")

    owners: dict[str, str] = {}
    if engagement_id is not None:
        engagement_id = _identity(engagement_id, "engagement_id")
        engagement = store.get_engagement(ctx, engagement_id)
        if engagement.client_id != scoped:
            raise TenantIsolationError("export engagement belongs to another client")
        owners[engagement_id] = engagement.client_id

    records = store.list_findings(ctx, client_id=scoped, engagement_id=engagement_id)
    findings: list[Finding] = []
    for record in records:
        if type(record) is not FindingRecord:
            raise ValueError("canonical finding record required")
        current_id = _identity(record.engagement_id, "finding engagement_id")
        if record.client_id != scoped:
            raise TenantIsolationError("finding belongs to another client")
        if engagement_id is not None and current_id != engagement_id:
            raise TenantIsolationError("finding belongs to another engagement")
        if current_id not in owners:
            owners[current_id] = store.get_engagement(ctx, current_id).client_id
        if owners[current_id] != scoped:
            raise TenantIsolationError("finding engagement ownership is inconsistent")
        findings.append(Finding(
            finding_id=record.finding_id,
            title=record.title,
            severity=record.severity,
            target=record.asset,
            remediation=record.remediation,
            retest_status=record.retest_status,
        ))
    return render_findings_csv(findings)
