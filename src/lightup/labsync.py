"""Bridge lab assessment results into the product domain.

This closes the product loop for lab runs: a lab baseline's findings become
regular :class:`~lightup.domain.FindingRecord` rows under an engagement — so
they show up in the operator dashboard and the client portal as
Finding → Impact → Fix → Retest — and a retest re-observes the (lab) target
and updates the retest status with honest semantics:

- issue gone        → ``FIXED``
- issue still there → ``FIX_PENDING`` (the fix is not effective yet)
- issue back after a ``FIXED`` verdict → ``REGRESSION``

Everything here is lab-only: retests re-use the baseline worker, which fails
closed on any non-loopback/non-private target.
"""

from __future__ import annotations

from .domain import AccessContext, DomainStore, EngagementRecord, FindingRecord
from .models import RetestStatus, Severity
from .workers import http_baseline

LAB_CLIENT_NAME = "Internal Lab"

_CHECK_ID_BY_TITLE = {
    title: check_id
    for check_id, _header, title, _severity, _impact, _remediation
    in http_baseline.BASELINE_CHECKS
}


def ensure_lab_engagement(
    store: DomainStore,
    ctx: AccessContext,
    engagement_name: str = "Continuous lab assessment",
) -> EngagementRecord:
    """Find or create the internal lab client + engagement (operator-only)."""
    ctx.require_operator("ensure_lab_engagement")
    client = next((c for c in store.list_clients(ctx) if c.name == LAB_CLIENT_NAME), None)
    if client is None:
        client = store.create_client(ctx, LAB_CLIENT_NAME)
    engagement = next(
        (e for e in store.list_engagements(ctx, client.client_id)
         if e.name == engagement_name),
        None,
    )
    if engagement is None:
        engagement = store.create_engagement(ctx, client.client_id, engagement_name)
    return engagement


def persist_lab_findings(
    store: DomainStore,
    ctx: AccessContext,
    engagement_id: str,
    labrun_result: dict,
) -> list[FindingRecord]:
    """Store a lab run's findings as domain findings with evidence references."""
    records = []
    for finding in labrun_result["findings"]:
        asset = finding.get("target") or labrun_result.get("target", "")
        evidence_ids = tuple(finding.get("evidence_ids", ())) or (
            (labrun_result["evidence_id"],) if "evidence_id" in labrun_result else ())
        records.append(
            store.record_finding(
                ctx,
                engagement_id,
                title=finding["finding"],
                severity=Severity(finding["severity"]),
                asset=asset,
                impact=finding["impact"],
                remediation=finding["fix"],
                evidence_ids=evidence_ids,
            )
        )
    return records


def persist_coverage(
    store: DomainStore,
    ctx: AccessContext,
    engagement_id: str,
    coverage_domains: dict[str, str],
) -> int:
    """Record a run's non-unknown coverage statuses on the engagement.

    Unknown stays unwritten: a later run must never downgrade an engagement's
    recorded coverage back to unknown by simply not touching a domain.
    """
    written = 0
    for capability_id, status in coverage_domains.items():
        if status == "unknown":
            continue
        store.set_coverage(ctx, engagement_id, capability_id, status)
        written += 1
    return written


def retest_finding(
    store: DomainStore, ctx: AccessContext, finding: FindingRecord
) -> FindingRecord:
    """Re-observe the lab target and update the finding's retest status."""
    check_id = _CHECK_ID_BY_TITLE.get(finding.title)
    if check_id is None:
        raise ValueError(
            f"finding {finding.finding_id!r} is not a known baseline check; "
            "automated retest is not available for it"
        )
    observation = http_baseline.observe(finding.asset)
    still_present = check_id in {issue.check_id for issue in observation.issues}
    if not still_present:
        status = RetestStatus.FIXED
    elif finding.retest_status is RetestStatus.FIXED:
        status = RetestStatus.REGRESSION
    else:
        status = RetestStatus.FIX_PENDING
    return store.set_retest_status(ctx, finding.finding_id, status)
