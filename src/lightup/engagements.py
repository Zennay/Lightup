from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum


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
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_current(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("authorization time must be timezone-aware")
        if self.revoked_at is not None:
            if self.revoked_at.tzinfo is None:
                raise ValueError("authorization revocation time must be timezone-aware")
            return False
        return self.valid_from <= now <= self.valid_until


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
