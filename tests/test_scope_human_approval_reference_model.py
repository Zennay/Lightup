"""Pure offline approval-envelope reference model. Never dispatches tools or targets.

This is an acceptance oracle, NOT LightUp's production authorization policy.
"""
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class ApprovalEnvelope:
    tenant: str
    revision: str
    reviewer: str
    issuer_lineage: str
    assets: frozenset[str]
    capabilities: frozenset[str]
    max_risk: int
    valid_from: datetime
    valid_until: datetime
    active: bool


@dataclass(frozen=True)
class Candidate:
    tenant: str
    revision: str
    asset: str
    capability: str
    risk: int
    mode: str


def reference_decision(
    candidate: Candidate, grant: ApprovalEnvelope | None, at: datetime
) -> bool:
    """Conditionally eligible only; executor must independently revalidate."""
    if type(candidate) is not Candidate or type(at) is not datetime:
        return False
    if at.tzinfo is None or at.utcoffset() is None:
        return False
    if grant is None or type(grant) is not ApprovalEnvelope:
        return False
    if not grant.active or candidate.mode != "active":
        return False
    strings = (candidate.tenant, candidate.revision, candidate.asset,
               candidate.capability, grant.tenant, grant.revision,
               grant.reviewer, grant.issuer_lineage)
    if any(type(value) is not str or not value.strip() for value in strings):
        return False
    if type(candidate.risk) is not int or type(grant.max_risk) is not int:
        return False
    if not 0 <= candidate.risk <= grant.max_risk:
        return False
    if type(grant.assets) is not frozenset or type(grant.capabilities) is not frozenset:
        return False
    if any(type(value) is not str or not value.strip()
           for value in grant.assets | grant.capabilities):
        return False
    start, end = grant.valid_from, grant.valid_until
    if type(start) is not datetime or type(end) is not datetime:
        return False
    if any(value.tzinfo is None or value.utcoffset() is None for value in (start, end)):
        return False
    try:
        return (
            start <= at < end
            and candidate.tenant == grant.tenant
            and candidate.revision == grant.revision
            and candidate.asset in grant.assets
            and candidate.capability in grant.capabilities
        )
    except (TypeError, ValueError, OverflowError):
        return False
