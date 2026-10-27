"""Offline LightUp INCUBATE capability registry posture lint, never authority.

This independent operator preflight checks a declared metadata profile. It does
not install an execution gate, attest source provenance or approve capability
activation. Changes to incubation assumptions always require review.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capability_registry_drift_review import _decode_manifest, _fingerprint

_INCUBATE_LAB_CAPABILITIES = frozenset({
    "ot-lab",
    "wireless-lab",
    "social-engineering-lab",
    "human-layer-lab",
    "physical-security-lab",
})


@dataclass(frozen=True)
class IncubationPostureReview:
    status: str
    reason: str
    metadata_fingerprint: str | None
    violations: tuple[tuple[str, str], ...]
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "metadata_fingerprint": self.metadata_fingerprint,
            "violations": [
                {"capability_id": identifier, "code": code}
                for identifier, code in self.violations
            ],
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def review_incubation_capability_posture(raw: bytes) -> IncubationPostureReview:
    """Check this checkout's declared incubation policy, not authorization.

    Valid canonical metadata is not automatically safe: compare it against the
    current PLAN/LAB ONLY safety assumptions without trusting another baseline.
    """
    try:
        records = _decode_manifest(raw)
        if any(name is None or description is None for _, _, name, description in records.values()):
            raise ValueError("legacy metadata incomplete")
    except (ValueError, TypeError, OverflowError, RecursionError):
        return IncubationPostureReview("HOLD", "invalid_or_incomplete_registry_metadata", None, ())

    violations: list[tuple[str, str]] = []
    for ident in sorted(records):
        state, activation, _, _ = records[ident]
        if not activation:
            violations.append((ident, "explicit_activation_required"))
        if ident in _INCUBATE_LAB_CAPABILITIES and state != "lab_only":
            violations.append((ident, "sensitive_lab_capability_reclassified"))
    for required in sorted(_INCUBATE_LAB_CAPABILITIES - records.keys()):
        violations.append((required, "required_lab_capability_missing"))
    violations.sort()
    return IncubationPostureReview(
        "HOLD" if violations else "REVIEW_ONLY",
        "incubation_posture_requires_independent_review" if violations else "incubation_metadata_only",
        _fingerprint(records),
        tuple(violations),
    )
