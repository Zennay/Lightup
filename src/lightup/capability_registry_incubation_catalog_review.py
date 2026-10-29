"""Closed-world, offline-only LightUp incubation capability catalog review.

This is a developer metadata preflight, not execution policy or an authorization
source. Changing the reference requires an explicit reviewed source change.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capability_registry_drift_review import _decode_manifest, _fingerprint

# Deliberately explicit M3/M7 incubation baseline. Do not derive the expected
# states from the same untrusted candidate being reviewed.
_PLANNED = frozenset({
    "external-attack-surface", "web-baseline", "api-baseline",
    "identity-access", "cloud-iam", "network-services", "host-hardening",
    "containers", "containers-kubernetes", "cicd", "supply-chain",
    "mobile", "desktop-client", "email-domain", "secrets",
    "database-storage", "saas-third-party", "business-logic",
    "abuse-fraud", "multi-tenancy", "logging-detection", "backup-recovery",
    "cryptography", "privacy-data", "ai-llm", "iot-embedded",
})
_LAB_ONLY = frozenset({
    "ot-lab", "wireless-lab", "social-engineering-lab",
    "human-layer-lab", "physical-security-lab",
})
_EXPECTED = {**dict.fromkeys(_PLANNED, "planning"), **dict.fromkeys(_LAB_ONLY, "lab_only")}

# Reviewed semantic metadata of the 31-entry source registry on main at
# 9e51da1585ba8c3d37610ec5a34bce088335713f. This is an ordinary
# code-review sentinel, NOT a signed manifest or trusted source attestation.
_REVIEWED_SEMANTIC_FINGERPRINT = (
    "sha256:37419dd71288587323bc112bf28ad2aafc6561118cde7750852307848cd4af16"
)


@dataclass(frozen=True)
class IncubationCatalogReview:
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
                {"capability_id": ident, "code": code}
                for ident, code in self.violations
            ],
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def review_incubation_catalog(raw: bytes) -> IncubationCatalogReview:
    """Deny unexpected/missing IDs, state changes, or disabled activation.

    REVIEW_ONLY is *never* an authority grant or merge/deployment approval.
    Only canonical bounded registry metadata can reach the review logic.
    """
    try:
        records = _decode_manifest(raw)
        if any(name is None or description is None for _, _, name, description in records.values()):
            raise ValueError("incomplete legacy metadata")
    except (ValueError, TypeError, OverflowError, RecursionError):
        return IncubationCatalogReview("HOLD", "invalid_or_incomplete_manifest", None, ())

    violations: list[tuple[str, str]] = []
    for ident in sorted(_EXPECTED.keys() - records.keys()):
        violations.append((ident, "required_capability_missing"))
    for ident in sorted(records):
        state, explicit_activation, _, _ = records[ident]
        if ident not in _EXPECTED:
            violations.append((ident, "unreviewed_capability_added"))
        elif state != _EXPECTED[ident]:
            violations.append((ident, "incubation_state_changed"))
        if explicit_activation is not True:
            violations.append((ident, "explicit_activation_required"))
    violations.sort()
    fingerprint = _fingerprint(records)
    if not violations and fingerprint != _REVIEWED_SEMANTIC_FINGERPRINT:
        return IncubationCatalogReview(
            "HOLD", "semantic_metadata_differs_from_reviewed_reference",
            fingerprint, (),
        )
    return IncubationCatalogReview(
        "HOLD" if violations else "REVIEW_ONLY",
        "catalog_change_requires_independent_review" if violations else "incubation_catalog_metadata_only",
        fingerprint,
        tuple(violations),
    )
