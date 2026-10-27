from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SignalCategory(str, Enum):
    ASSET = "asset"
    TECHNOLOGY = "technology"
    CONFIGURATION = "configuration"
    VULNERABILITY_CORRELATION = "vulnerability_correlation"
    DOMAIN_EMAIL = "domain_email"
    THIRD_PARTY_EXPOSURE = "third_party_exposure"


@dataclass(frozen=True)
class ProspectSignal:
    category: SignalCategory
    summary: str
    source: str
    confidence: float
    public_source: bool
    requires_target_interaction: bool = False

    def validate_for_unauthorized_discovery(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if type(self.public_source) is not bool:
            raise ValueError("public_source must be an exact boolean")
        if type(self.requires_target_interaction) is not bool:
            raise ValueError("requires_target_interaction must be an exact boolean")
        if self.public_source is not True:
            raise PermissionError("unauthorized discovery requires a public source")
        if self.requires_target_interaction is True:
            raise PermissionError("unauthorized discovery cannot require target interaction")


@dataclass
class ProspectProfile:
    prospect_id: str
    organization_name: str
    signals: list[ProspectSignal] = field(default_factory=list)

    def add_signal(self, signal: ProspectSignal) -> None:
        signal.validate_for_unauthorized_discovery()
        self.signals.append(signal)

    @property
    def confidence(self) -> float:
        if not self.signals:
            return 0.0
        return sum(item.confidence for item in self.signals) / len(self.signals)
