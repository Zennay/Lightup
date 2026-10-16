"""Isolated canonical, fictional scope-review note quarantine.

This is a *non-authorizing*, intentionally narrow review preflight, not a
general-purpose PII/secret scanner or a proof that a note is safe to publish.
Only specially formatted examples in the reserved example.test namespace can
ever receive REVIEW_ONLY. Arbitrary pasted free text is always HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

_MAX_NOTES = 16
_MAX_NOTE_BYTES = 4096
_MAX_TOTAL_BYTES = 32768

# Accept one complete, explicitly fictional record: never "find" a good-looking
# substring inside attacker-controlled notes. Canonical grammar is deliberately
# much narrower than the production asset/capability model.
_CANONICAL_NOTE = re.compile(
    r"\AAsset (?P<host>(?:[a-z]|[a-z][a-z0-9-]{0,61}[a-z0-9])\.example\.test); "
    r"capability (?P<capability>[a-z][a-z0-9_]{0,47}); proposed risk (?P<risk>[1-5])\.\Z"
)
_FICTIONAL_CAPABILITIES = frozenset({
    "header_read", "tls_review", "service_inventory", "passive_discovery",
})
_HOLD_NOTICE = "HOLD — offline handoff quarantined; no input echoed. NOT AUTHORIZED."
_REVIEW_NOTICE = (
    "REVIEW_ONLY — fictional notes still require independent human privacy "
    "and scope review. NOT AUTHORIZED."
)


@dataclass(frozen=True)
class DisclosureVerdict:
    status: str
    notice: str
    reviewed_notes: int
    # Cannot even pass authority flags to this class's constructor. This is an
    # output-shape guard, not cryptographic integrity or permission enforcement.
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Refuse forged verdict words/counts even in direct constructions.

        Never treat this as an authenticated or tamper-proof object: this is
        just one more shape-invariant against accidental downstream misuse.
        """
        if not (type(self.status) is str and type(self.notice) is str
                and type(self.reviewed_notes) is int):
            raise ValueError("invalid fictional review verdict")
        if self.status == "HOLD":
            valid = self.notice == _HOLD_NOTICE and self.reviewed_notes == 0
        elif self.status == "REVIEW_ONLY":
            valid = (self.notice == _REVIEW_NOTICE
                     and 1 <= self.reviewed_notes <= _MAX_NOTES)
        else:
            valid = False
        if not valid:
            raise ValueError("invalid fictional review verdict")


def _hold() -> DisclosureVerdict:
    return DisclosureVerdict("HOLD", _HOLD_NOTICE, 0)


def review_fictional_handoff_notes(notes: object) -> DisclosureVerdict:
    """Atomically review 1–16 exact builtin strings, without source-text echo.

    REVIEW_ONLY is solely a fictional-format check. It is never authorization
    to publish, issue grants, scan, execute, dispatch, or treat notes as consent.
    On *any* malformed or conflicting record, return the same generic HOLD.
    """
    if type(notes) is not tuple or not (1 <= len(notes) <= _MAX_NOTES):
        return _hold()

    total_bytes = 0
    seen = set()
    for note in notes:
        if type(note) is not str or not note:
            return _hold()
        try:
            size = len(note.encode("ascii", "strict"))
        except UnicodeError:
            return _hold()
        total_bytes += size
        if size > _MAX_NOTE_BYTES or total_bytes > _MAX_TOTAL_BYTES:
            return _hold()

        parsed = _CANONICAL_NOTE.fullmatch(note)
        if parsed is None:
            return _hold()
        capability = parsed.group("capability")
        # Do not display IDNA/punycode lookalike labels as reassuring examples.
        if parsed.group("host").startswith("xn--"):
            return _hold()
        if capability not in _FICTIONAL_CAPABILITIES:
            return _hold()
        key = (parsed.group("host"), capability)
        if key in seen:
            # A repeated asset+capability with any risk is ambiguous and must
            # not be represented as two independently accepted proposals.
            return _hold()
        seen.add(key)

    return DisclosureVerdict("REVIEW_ONLY", _REVIEW_NOTICE, len(notes))
