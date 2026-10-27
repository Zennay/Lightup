"""Atomic non-authorizing incubation capability dossier for human local review.

Combines three independent local metadata reviewers. Never treats a favorable
subset as a permit; any malformed/incoherent component produces atomic HOLD.
This code is not wired into LightUp execution or trusted authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .capability_registry_incubation_catalog_review import review_incubation_catalog
from .capability_registry_incubation_review import review_incubation_capability_posture
from .capability_registry_incubation_field_review import review_incubation_fields

_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_CATALOG_CODES = frozenset({
    "required_capability_missing", "unreviewed_capability_added",
    "incubation_state_changed", "explicit_activation_required",
})
_POSTURE_CODES = frozenset({
    "explicit_activation_required", "sensitive_lab_capability_reclassified",
    "required_lab_capability_missing",
})
_FIELD_CODES = frozenset({"name", "description"})


@dataclass(frozen=True)
class IncubationDossier:
    status: str
    reason: str
    catalog_status: str
    posture_status: str
    fields_status: str
    fingerprint: str | None
    catalog_violations: tuple[tuple[str, str], ...]
    posture_violations: tuple[tuple[str, str], ...]
    changed_fields: tuple[tuple[str, tuple[str, ...]], ...]
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "component_statuses": {
                "catalog": self.catalog_status,
                "posture": self.posture_status,
                "fields": self.fields_status,
            },
            "fingerprint": self.fingerprint,
            "catalog_violations": [
                {"capability_id": ident, "code": code}
                for ident, code in self.catalog_violations
            ],
            "posture_violations": [
                {"capability_id": ident, "code": code}
                for ident, code in self.posture_violations
            ],
            "changed_fields": {
                ident: list(labels) for ident, labels in self.changed_fields
            },
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _invalid() -> IncubationDossier:
    return IncubationDossier("HOLD", "invalid_or_incoherent_registry_dossier",
                             "HOLD", "HOLD", "HOLD", None, (), (), ())


def _safe_code_pairs(
    values: object, allowed: frozenset[str],
) -> bool:
    if type(values) is not tuple or len(values) > 256:
        return False
    for item in values:
        if (type(item) is not tuple or len(item) != 2 or
                type(item[0]) is not str or _ID.fullmatch(item[0]) is None or
                type(item[1]) is not str or item[1] not in allowed):
            return False
    return tuple(sorted(values)) == values and len(set(values)) == len(values)


def _safe_fields(values: object) -> bool:
    if type(values) is not tuple or len(values) > 128:
        return False
    ids: list[str] = []
    for item in values:
        if type(item) is not tuple or len(item) != 2:
            return False
        ident, fields = item
        if (type(ident) is not str or _ID.fullmatch(ident) is None or
                type(fields) is not tuple or not fields or len(fields) > 2 or
                any(type(f) is not str or f not in _FIELD_CODES for f in fields) or
                tuple(label for label in ("name", "description") if label in fields) != fields):
            return False
        ids.append(ident)
    return ids == sorted(set(ids))



def _coherent_components(catalog: object, posture: object, fields: object,
                         fingerprint: str) -> bool:
    """Prove that a favorable component status matches its actual evidence.

    Do not trust one component's status label without verifying its fixed,
    version-pinned reason, violation cardinality and sibling relationships.
    This is a *local* review-consistency test, never independent attestation.
    """
    if any(
        type(value) is not str
        for value in (catalog.status, catalog.reason, posture.status,
                      posture.reason, fields.status, fields.reason)
    ):
        return False
    if posture.status == "REVIEW_ONLY":
        if posture.reason != "incubation_metadata_only" or posture.violations:
            return False
    elif posture.status == "HOLD":
        if (posture.reason != "incubation_posture_requires_independent_review"
                or not posture.violations):
            return False
    else:
        return False

    if catalog.status == "REVIEW_ONLY":
        return (
            catalog.reason == "incubation_catalog_metadata_only"
            and not catalog.violations
            and posture.status == "REVIEW_ONLY"
            and fields.status == "REVIEW_ONLY"
            and fields.reason == "unchanged_reviewed_fields_only"
            and fields.catalog_fingerprint == fingerprint
            and not fields.changed_fields
        )
    if catalog.status != "HOLD":
        return False

    if catalog.reason == "semantic_metadata_differs_from_reviewed_reference":
        return (
            not catalog.violations
            and posture.status == "REVIEW_ONLY"
            and fields.status == "HOLD"
            and fields.reason == "metadata_fields_require_review"
            and fields.catalog_fingerprint == fingerprint
            and bool(fields.changed_fields)
        )

    if catalog.reason != "catalog_change_requires_independent_review":
        return False
    if not catalog.violations:
        return False
    if (
        fields.status != "HOLD"
        or fields.reason != "invalid_or_changed_catalog_boundary"
        or fields.catalog_fingerprint is not None
        or fields.changed_fields
    ):
        return False

    catalog_changes = set(catalog.violations)
    for ident, code in posture.violations:
        match = {
            "explicit_activation_required": "explicit_activation_required",
            "sensitive_lab_capability_reclassified": "incubation_state_changed",
            "required_lab_capability_missing": "required_capability_missing",
        }.get(code)
        if (ident, match) not in catalog_changes:
            return False
    return True


def review_atomic_incubation_dossier(raw: bytes) -> IncubationDossier:
    """Review identical raw bytes across all three; never issue runtime authority."""
    if type(raw) is not bytes:
        return _invalid()
    catalog = review_incubation_catalog(raw)
    posture = review_incubation_capability_posture(raw)
    fields = review_incubation_fields(raw)
    checks = (catalog.status, posture.status, fields.status)
    if any(value not in ("HOLD", "REVIEW_ONLY") for value in checks):
        return _invalid()
    fingerprint = catalog.metadata_fingerprint
    if (type(fingerprint) is not str or _HASH.fullmatch(fingerprint) is None or
            posture.metadata_fingerprint != fingerprint):
        return _invalid()
    if (not _safe_code_pairs(catalog.violations, _CATALOG_CODES) or
            not _safe_code_pairs(posture.violations, _POSTURE_CODES) or
            not _safe_fields(fields.changed_fields)):
        return _invalid()
    if fields.catalog_fingerprint not in (fingerprint, None):
        return _invalid()
    if fields.catalog_fingerprint is None and fields.changed_fields:
        return _invalid()
    if catalog.status == "REVIEW_ONLY" and fields.status != "REVIEW_ONLY":
        return _invalid()
    if catalog.status == "HOLD" and fields.status == "REVIEW_ONLY":
        return _invalid()
    if fields.status == "REVIEW_ONLY" and fields.changed_fields:
        return _invalid()
    if fields.status == "HOLD" and fields.changed_fields and not (
        catalog.reason == "semantic_metadata_differs_from_reviewed_reference"
    ):
        return _invalid()
    if not _coherent_components(catalog, posture, fields, fingerprint):
        return _invalid()

    all_review_only = checks == ("REVIEW_ONLY", "REVIEW_ONLY", "REVIEW_ONLY")
    return IncubationDossier(
        "REVIEW_ONLY" if all_review_only else "HOLD",
        "unchanged_declared_source_metadata_only" if all_review_only else "one_or_more_checks_require_review",
        *checks,
        fingerprint,
        catalog.violations,
        posture.violations,
        fields.changed_fields,
    )
