"""Offline review binding a declared capability history to the local source registry.

This is *not* code provenance, a trusted Git checkout attestation or authority:
it only establishes consistency against a separately exported local registry.
No filesystem, network, grant or target interaction happens in this module.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capability_registry_drift_review import review_capability_registry_drift
from .capability_registry_history_review import review_capability_registry_history


@dataclass(frozen=True)
class CheckoutRegistryReview:
    status: str
    reason: str
    history_status: str
    latest_matches_local_registry: bool
    history_transition_count: int
    latest_fingerprint: str | None
    local_registry_fingerprint: str | None
    current_registry_changed_fields: tuple[tuple[str, tuple[str, ...]], ...]
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "history_status": self.history_status,
            "latest_matches_local_registry": self.latest_matches_local_registry,
            "history_transition_count": self.history_transition_count,
            "latest_fingerprint": self.latest_fingerprint,
            "local_registry_fingerprint": self.local_registry_fingerprint,
            "current_registry_changed_fields": {
                name: list(fields) for name, fields in self.current_registry_changed_fields
            },
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _invalid() -> CheckoutRegistryReview:
    return CheckoutRegistryReview(
        "HOLD", "invalid_history_or_local_registry", "HOLD", False, 0, None, None, (),
    )


def review_history_against_local_registry(
    declared_snapshots: tuple[bytes, ...], local_registry_manifest: bytes,
) -> CheckoutRegistryReview:
    """Review every transition and separately compare final manifest to checkout.

    A same-version history that does not match the actual local registry is
    HOLD, including a legacy three-field to complete five-field mismatch.
    Intermediate historical changes also remain HOLD even on a current match.
    """
    if type(declared_snapshots) is not tuple or type(local_registry_manifest) is not bytes:
        return _invalid()
    history = review_capability_registry_history(declared_snapshots)
    if history.snapshot_count < 2:
        return _invalid()
    actual = review_capability_registry_drift(local_registry_manifest, local_registry_manifest)
    if actual.status != "REVIEW_ONLY":
        return _invalid()
    current = review_capability_registry_drift(declared_snapshots[-1], local_registry_manifest)
    if current.baseline_fingerprint is None or current.candidate_fingerprint is None:
        return _invalid()
    if current.baseline_fingerprint != history.fingerprint_history[-1]:
        return _invalid()
    matches = current.status == "REVIEW_ONLY"
    drifted = history.status != "REVIEW_ONLY"
    return CheckoutRegistryReview(
        status="HOLD" if drifted or not matches else "REVIEW_ONLY",
        reason=(
            "latest_snapshot_differs_from_local_registry"
            if not matches else
            "declared_historical_drift_requires_review"
            if drifted else
            "declared_history_matches_local_registry_metadata_only"
        ),
        history_status=history.status,
        latest_matches_local_registry=matches,
        history_transition_count=len(history.transitions),
        latest_fingerprint=current.baseline_fingerprint,
        local_registry_fingerprint=current.candidate_fingerprint,
        current_registry_changed_fields=current.changed_fields,
    )
