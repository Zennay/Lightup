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

    def __post_init__(self) -> None:
        if type(self.statuses) is not tuple:
            raise TypeError("coverage statuses must be an immutable tuple")

        expected_ids = tuple(capability.capability_id for capability in get_capabilities())
        expected_id_set = set(expected_ids)
        actual_ids: list[str] = []

        for row in self.statuses:
            if type(row) is not tuple or len(row) != 2:
                raise TypeError("coverage rows must be exact (capability_id, status) tuples")
            capability_id, status = row
            if type(capability_id) is not str or not capability_id:
                raise TypeError("coverage capability_id must be a non-empty string")
            if type(status) is not CoverageStatus:
                raise TypeError("coverage status must be an exact CoverageStatus member")
            actual_ids.append(capability_id)

        if len(set(actual_ids)) != len(actual_ids):
            raise ValueError("coverage capability ids must be unique")

        unknown_ids = set(actual_ids) - expected_id_set
        if unknown_ids:
            raise ValueError(f"unknown capability ids: {sorted(unknown_ids)}")

        missing_ids = expected_id_set - set(actual_ids)
        if missing_ids:
            raise ValueError(f"missing capability ids: {sorted(missing_ids)}")

        if tuple(actual_ids) != expected_ids:
            raise ValueError("coverage rows must follow canonical registry order")

    @staticmethod
    def build(assessed: dict[str, CoverageStatus] | None = None) -> "CoverageReport":
        assessed = dict(assessed or {})
        capabilities = get_capabilities()
        known_ids = {capability.capability_id for capability in capabilities}
        unknown_keys = set(assessed) - known_ids
        if unknown_keys:
            raise ValueError(f"unknown capability ids: {sorted(unknown_keys)}")
        statuses = tuple(
            (
                capability.capability_id,
                assessed.get(capability.capability_id, CoverageStatus.UNKNOWN),
            )
            for capability in capabilities
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
