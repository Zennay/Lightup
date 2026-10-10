"""Non-authorizing retest transition preflight for real LightUp Finding objects.

Never equate additional evidence or a FIXED status with verification. This
offline comparison cannot authenticate the evidence source or authorize work.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, RetestStatus, Severity

_MAX_FINDING_TEXT = 4096
_MAX_EVIDENCE_ITEMS = 64
_MAX_EVIDENCE_TEXT = 2048
_MAX_EVIDENCE_BYTES = 65536


@dataclass(frozen=True)
class RetestTransitionPreflight:
    ready_for_independent_review: bool
    reasons: tuple[str, ...]
    new_evidence_count: int
    externally_verified: bool = False
    remediation_authorized: bool = False
    release_authorized: bool = False

    def as_dict(self) -> dict[str, object]:
        """Return only bounded non-sensitive diagnostics, never evidence text."""
        return {
            "ready_for_independent_review": self.ready_for_independent_review,
            "reasons": list(self.reasons),
            "new_evidence_count": self.new_evidence_count,
            "externally_verified": False,
            "remediation_authorized": False,
            "release_authorized": False,
        }


def _text(value: object, *, max_chars: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= max_chars
        and value.strip() == value
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _evidence(items: object) -> set[str] | None:
    if type(items) is not list or len(items) > _MAX_EVIDENCE_ITEMS:
        return None
    result: set[str] = set()
    total = 0
    for entry in items:
        if not _text(entry, max_chars=_MAX_EVIDENCE_TEXT):
            return None
        total += len(entry.encode("utf-8"))
        if total > _MAX_EVIDENCE_BYTES or entry in result:
            return None
        result.add(entry)
    return result


def _shape(finding: object) -> set[str] | None:
    if type(finding) is not Finding:
        return None
    if type(finding.severity) is not Severity:
        return None
    if type(finding.retest_status) is not RetestStatus:
        return None
    if not all(
        _text(getattr(finding, field), max_chars=_MAX_FINDING_TEXT)
        for field in ("finding_id", "title", "target", "remediation")
    ):
        return None
    return _evidence(finding.evidence)


def preflight_retest_transition(
    previous: Finding,
    candidate: Finding,
) -> RetestTransitionPreflight:
    """Review whether a claimed retest delta can go to an independent reviewer.

    Both finding snapshots are untrusted. A successful result proves only
    structural evidence retention and at least one added item. It NEVER proves
    the evidence was collected, is recent, belongs to a tenant, establishes a
    fix, or permits a scanner, mitigation, export, or release.
    """
    old = _shape(previous)
    new = _shape(candidate)
    if old is None or new is None:
        return RetestTransitionPreflight(False, ("invalid_finding_shape",), 0)

    reasons: list[str] = []
    if candidate.finding_id != previous.finding_id:
        reasons.append("finding_identity_changed")
    if candidate.target != previous.target:
        reasons.append("target_identity_changed")
    if candidate.severity is not previous.severity:
        reasons.append("severity_changed")
    if candidate.title != previous.title:
        reasons.append("title_changed")
    if not old.issubset(new):
        reasons.append("historical_evidence_removed")
    delta = new - old
    if not delta:
        reasons.append("no_new_evidence")

    return RetestTransitionPreflight(
        not reasons,
        tuple(reasons),
        len(delta),
    )
