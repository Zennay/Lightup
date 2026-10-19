"""Optional tenant-selected finding CSV with strict presentation preflight.

This is an isolated, unmounted producer reference. No credentials are checked
here: AccessContext MUST come from the trusted login/session layer. Default
CLI/web/service exporters are deliberately unchanged until their owners review
a shared selection-and-renderer integration. The result is not a verified
finding, approved remediation, or safe-to-share secrets determination.
"""
from __future__ import annotations

from .domain import (
    AccessContext,
    DomainStore,
    FindingRecord,
    Role,
    TenantIsolationError,
)
from .finding_export_unicode_integrity import render_findings_csv_checked
from .models import Finding


def _canonical_id(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError("canonical nonempty identity required")
    return value


def render_tenant_findings_csv_checked(
    store: DomainStore,
    ctx: AccessContext,
    client_id: str,
    *,
    engagement_id: str | None = None,
) -> str:
    """Return a bounded, Unicode-checked CSV after existing tenant admission.

    A caller MUST acquire `ctx` from current trusted authentication. This
    function does not refresh user sessions, issue grants, claim fix/retest
    verification, or accept evidence from an external target.
    """
    if type(store) is not DomainStore or type(ctx) is not AccessContext:
        raise ValueError("canonical store and authenticated access context required")
    if type(ctx.role) is not Role:
        raise ValueError("canonical role required")
    _canonical_id(ctx.user_id)
    if ctx.role is not Role.OPERATOR:
        _canonical_id(ctx.client_id)

    requested_client_id = _canonical_id(client_id)
    scoped_client_id = ctx.resolve_client(
        requested_client_id, "export_findings_unicode_checked"
    )
    if scoped_client_id != requested_client_id:
        raise TenantIsolationError("export client selection mismatch")
    client = store.get_client(ctx, scoped_client_id)
    if client.client_id != scoped_client_id:
        raise TenantIsolationError("export client owner mismatch")

    owners: dict[str, str] = {}
    if engagement_id is not None:
        engagement_id = _canonical_id(engagement_id)
        engagement = store.get_engagement(ctx, engagement_id)
        if engagement.client_id != scoped_client_id:
            raise TenantIsolationError("export engagement owner mismatch")
        owners[engagement_id] = engagement.client_id

    # Apply the canonical StateStore/DomainStore's tenant-filtered read, never
    # a hand-written unscoped SQLite query. All records are checked before
    # the opt-in CSV preflight builds ANY output.
    records = store.list_findings(
        ctx, client_id=scoped_client_id, engagement_id=engagement_id
    )
    projected: list[Finding] = []
    for record in records:
        if type(record) is not FindingRecord:
            raise ValueError("canonical finding record required")
        source_engagement = _canonical_id(record.engagement_id)
        if record.client_id != scoped_client_id:
            raise TenantIsolationError("finding client owner mismatch")
        if engagement_id is not None and source_engagement != engagement_id:
            raise TenantIsolationError("finding engagement mismatch")
        if source_engagement not in owners:
            owners[source_engagement] = store.get_engagement(
                ctx, source_engagement
            ).client_id
        if owners[source_engagement] != scoped_client_id:
            raise TenantIsolationError("finding engagement owner mismatch")
        projected.append(Finding(
            finding_id=record.finding_id,
            title=record.title,
            severity=record.severity,
            target=record.asset,
            remediation=record.remediation,
            retest_status=record.retest_status,
        ))

    return render_findings_csv_checked(projected)
