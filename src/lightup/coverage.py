"""Explicit coverage tracking.

LightUp never claims "everything was tested". Every run reports, per security
domain in the capability registry, what actually happened. Zero findings with
large unknown coverage is not a clean bill of health, and reports must say so.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .capabilities import get_capabilities


class CoverageStatus(str, Enum):
    ASSESSED = "assessed"
    PARTIALLY_ASSESSED = "partially_assessed"
    NOT_APPLICABLE = "not_applicable"
    NOT_AUTHORIZED = "not_authorized"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CoverageReport:
    """Coverage status for every registered capability, defaulting to unknown."""

    statuses: tuple[tuple[str, CoverageStatus], ...]

    @staticmethod
    def build(assessed: dict[str, CoverageStatus] | None = None) -> "CoverageReport":
        assessed = dict(assessed or {})
        known_ids = {c.capability_id for c in get_capabilities()}
        unknown_keys = set(assessed) - known_ids
        if unknown_keys:
            raise ValueError(f"unknown capability ids: {sorted(unknown_keys)}")
        statuses = tuple(
            (c.capability_id, assessed.get(c.capability_id, CoverageStatus.UNKNOWN))
            for c in get_capabilities()
        )
        return CoverageReport(statuses)

    def counts(self) -> dict[str, int]:
        result = {status.value: 0 for status in CoverageStatus}
        for _capability_id, status in self.statuses:
            result[status.value] += 1
        return result

    @property
    def is_materially_unknown(self) -> bool:
        """True when unknown domains outnumber assessed ones."""
        counts = self.counts()
        covered = counts[CoverageStatus.ASSESSED.value] + counts[
            CoverageStatus.PARTIALLY_ASSESSED.value]
        return counts[CoverageStatus.UNKNOWN.value] > covered

    def to_dict(self) -> dict:
        return {
            "domains": {capability_id: status.value
                        for capability_id, status in self.statuses},
            "counts": self.counts(),
            "clean_bill_of_health": False if self.is_materially_unknown else None,
            "note": ("coverage is materially unknown; zero findings must not be "
                     "read as a clean bill of health")
                    if self.is_materially_unknown else "",
        }
