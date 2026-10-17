from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum

from .timewindow import canonical_instant, evaluation_instant


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    AUTHORIZATION_PENDING = "authorization_pending"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    REMEDIATION = "remediation"
    RETEST = "retest"
    CLOSED = "closed"


class AssessmentMode(str, Enum):
    ANALYSIS_ONLY = "analysis_only"
    PASSIVE_DISCOVERY = "passive_discovery"
    LAB_AUTONOMOUS = "lab_autonomous"
    AUTHORIZED_ASSESSMENT = "authorized_assessment"


class RiskLevel(IntEnum):
    ANALYSIS_ONLY = 0
    PASSIVE = 1
    LOW_IMPACT = 2
    STANDARD = 3
    ELEVATED = 4
    DESTRUCTIVE_LAB_ONLY = 5


@dataclass(frozen=True)
class ScopeDefinition:
    assets: tuple[str, ...]
    max_risk: RiskLevel
    allowed_capabilities: tuple[str, ...] = ()
    excluded_assets: tuple[str, ...] = ()

    def allows_asset(self, asset: str) -> bool:
        normalized = asset.strip().lower()
        allowed = {item.strip().lower() for item in self.assets}
        excluded = {item.strip().lower() for item in self.excluded_assets}
        return normalized in allowed and normalized not in excluded

    def allows_capability(self, capability_id: str) -> bool:
        return not self.allowed_capabilities or capability_id in self.allowed_capabilities


@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: str
    client_id: str
    engagement_id: str
    approved_by: str
    reference: str
    scope: ScopeDefinition
    valid_from: datetime
    valid_until: datetime
    recurring_retest_allowed: bool = False

    def is_current(self, now: datetime | None = None) -> bool:
        now = evaluation_instant(now)
        start = canonical_instant(self.valid_from)
        until = canonical_instant(self.valid_until)
        if start is None or until is None:
            return False
        return start <= now <= until


@dataclass(frozen=True)
class AssessmentRequest:
    request_id: str
    client_id: str
    requested_assets: tuple[str, ...]
    requested_mode: AssessmentMode
    requested_risk: RiskLevel
    requested_by: str
    notes: str = ""


@dataclass
class Engagement:
    engagement_id: str
    client_id: str
    name: str
    status: EngagementStatus = EngagementStatus.DRAFT
    authorization: AuthorizationGrant | None = None
    metadata: dict[str, str] = field(default_factory=dict)
