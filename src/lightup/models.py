from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .timewindow import canonical_instant, evaluation_instant


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RetestStatus(str, Enum):
    NOT_TESTED = "not_tested"
    FIX_PENDING = "fix_pending"
    FIXED = "fixed"
    REGRESSION = "regression"


@dataclass(frozen=True)
class Authorization:
    owner: str
    reference: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    def is_current(self, now: datetime | None = None) -> bool:
        now = evaluation_instant(now)
        # ``None`` is the only "unbounded" marker; any other non-canonical
        # bound (0, False, "", subclasses, naive datetimes) fails closed.
        if self.valid_from is not None:
            start = canonical_instant(self.valid_from)
            if start is None or now < start:
                return False
        if self.valid_until is not None:
            until = canonical_instant(self.valid_until)
            if until is None or now > until:
                return False
        return True


@dataclass(frozen=True)
class Target:
    value: str
    authorization: Authorization | None = None
    labels: tuple[str, ...] = ()


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    target: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    retest_status: RetestStatus = RetestStatus.NOT_TESTED
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if not self.title.strip():
            raise ValueError("title is required")
        if not self.target.strip():
            raise ValueError("target is required")
        if not self.remediation.strip():
            raise ValueError("remediation is required")
