"""Offline human-readable, non-authorizing current incubation dossier report.

This module turns the *reviewed* three-gate capability metadata decision
into a bounded, fixed-vocabulary Markdown report. It never reads targets,
executes capabilities or treats a metadata match as a grant or release.
"""
from __future__ import annotations

from .capability_registry_incubation_dossier import (
    _CATALOG_CODES,
    _FIELD_CODES,
    _HASH,
    _ID,
    _POSTURE_CODES,
    review_atomic_incubation_dossier,
)

_TITLE = "# LightUp — Incubation Capability Review"
_BANNER = (
    "**Authority: NONE.** This is developer metadata review only; not a "
    "customer consent, grant, scan permit, merge approval, release or deployment."
)
_FOOTER = (
    "\nNo target interaction, network assessment, grant issuance, "
    "operator step-up, production write, or active security testing "
    "is authorized by this report.\n"
)
_REASONS = {
    "unchanged_declared_source_metadata_only",
    "one_or_more_checks_require_review",
    "invalid_or_incoherent_registry_dossier",
}
_AREAS = ("catalog", "posture", "fields")


def _generic_hold() -> tuple[str, int]:
    return (
        "\n".join((
            _TITLE, "",
            _BANNER, "",
            "**Verdict:** `HOLD`",
            "**Reason:** invalid or inconsistent local review metadata.",
            "**Fingerprint:** unavailable",
            "",
            "Source metadata must be reviewed independently before any change.",
        )) + "\n" + _FOOTER,
        2,
    )


def _valid_pair(ident: object, code: object, area: str) -> bool:
    allowed = _CATALOG_CODES if area == "catalog" else _POSTURE_CODES if area == "posture" else _FIELD_CODES
    return (
        type(ident) is str and len(ident) <= 64 and _ID.fullmatch(ident) is not None
        and type(code) is str and code in allowed
    )


def render_incubation_dossier_markdown(raw: bytes) -> tuple[str, int]:
    """Return (bounded Markdown, nonzero exit code) from local metadata bytes."""
    try:
        dossier = review_atomic_incubation_dossier(raw)
        if dossier.status not in ("HOLD", "REVIEW_ONLY") or dossier.reason not in _REASONS:
            return _generic_hold()
        if dossier.status == "REVIEW_ONLY" and dossier.reason != "unchanged_declared_source_metadata_only":
            return _generic_hold()
        if dossier.status == "HOLD" and dossier.reason == "unchanged_declared_source_metadata_only":
            return _generic_hold()
        components = (dossier.catalog_status, dossier.posture_status, dossier.fields_status)
        if any(type(status) is not str or status not in ("REVIEW_ONLY", "HOLD") for status in components):
            return _generic_hold()
        if dossier.status == "REVIEW_ONLY" and components != ("REVIEW_ONLY",) * 3:
            return _generic_hold()
        if dossier.status == "HOLD" and components == ("REVIEW_ONLY",) * 3:
            return _generic_hold()
        fingerprint = dossier.fingerprint
        if fingerprint is not None and (
            type(fingerprint) is not str or _HASH.fullmatch(fingerprint) is None
        ):
            return _generic_hold()
        if dossier.status == "REVIEW_ONLY" and fingerprint is None:
            return _generic_hold()

        rows: list[tuple[str, str, str]] = []
        for ident, code in dossier.catalog_violations:
            if not _valid_pair(ident, code, "catalog"):
                return _generic_hold()
            rows.append((ident, "catalog", code))
        for ident, code in dossier.posture_violations:
            if not _valid_pair(ident, code, "posture"):
                return _generic_hold()
            rows.append((ident, "posture", code))
        for ident, fields in dossier.changed_fields:
            if type(fields) is not tuple or not fields:
                return _generic_hold()
            for code in fields:
                if not _valid_pair(ident, code, "fields"):
                    return _generic_hold()
                rows.append((ident, "fields", code))
        if dossier.status == "REVIEW_ONLY" and rows:
            return _generic_hold()
        if dossier.reason == "invalid_or_incoherent_registry_dossier" and (
            fingerprint is not None or rows
        ):
            return _generic_hold()

        text = [
            _TITLE, "", _BANNER, "",
            f"**Verdict:** `{dossier.status}`",
            "**Meaning:** " + (
                "The local source registry matches this code-reviewed incubation "
                "reference. Independent operator review is still required."
                if dossier.status == "REVIEW_ONLY"
                else "One or more local controls require independent human review."
            ),
            f"**Fingerprint:** `{fingerprint}`" if fingerprint is not None
            else "**Fingerprint:** unavailable", "",
            "## Independent checks", "",
            "| Reviewed boundary | Result |",
            "| --- | --- |",
        ]
        for label, status in zip(
            ("Closed-world catalog", "Incubation lab / activation posture",
             "Name and description metadata"),
            components,
        ):
            text.append(f"| {label} | `{status}` |")
        text += ["", "## Changes for human review", ""]
        if rows:
            text += [
                "| Capability ID | Area | Fixed review code |",
                "| --- | --- | --- |",
            ]
            for ident, area, code in sorted(set(rows)):
                text.append(f"| `{ident}` | `{area}` | `{code}` |")
        else:
            text.append(
                "No field-level details can be disclosed for this status."
                if dossier.status == "HOLD"
                else "No capability metadata changes against the checked-in reference."
            )
        text += ["", _FOOTER.rstrip(), ""]
        report = "\n".join(text)
        if len(report) > 32768:
            return _generic_hold()
        return report, 3 if dossier.status == "REVIEW_ONLY" else 2
    except (ValueError, TypeError, OverflowError, RecursionError, AttributeError):
        return _generic_hold()
