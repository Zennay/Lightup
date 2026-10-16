"""Bounded, non-authorizing quarantine for *fictional* scope-review handoff notes.

This is a deliberately conservative privacy linter, NOT a reliable secret detector,
permission verifier, sanitizer, or a gate connected to LightUp runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_MAX_NOTES = 16
_MAX_NOTE_BYTES = 4096
_MAX_TOTAL_BYTES = 32768
_ALLOWED_CHARS = re.compile(r"[A-Za-z0-9 .;:,=_()!\-\n]+\Z")
_DOTTED_NAME = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9_-])")
_RESERVED_HOST = re.compile(r"(?:[a-z]|[a-z][a-z0-9-]{0,61}[a-z0-9])\.example\.test\Z")
_IPV4_SHAPE = re.compile(r"(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9])")
_IPV6_SHAPE = re.compile(r"(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}")
_SECRET_HINT = re.compile(
    r"(?i)(?:\b(?:password|passwd|secret|bearer|api[_-]?key|private[_-]?key|access[_-]?token)\b|\bsk-[A-Za-z0-9]+)"
)
_GENERIC_HOLD = "HOLD — offline handoff quarantined; no input echoed. NOT AUTHORIZED."
_REVIEW = "REVIEW_ONLY — fictional notes still require independent human privacy and scope review. NOT AUTHORIZED."


@dataclass(frozen=True)
class DisclosureVerdict:
    status: str
    notice: str
    reviewed_notes: int
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


def _hold() -> DisclosureVerdict:
    return DisclosureVerdict("HOLD", _GENERIC_HOLD, 0)


def review_fictional_handoff_notes(notes: object) -> DisclosureVerdict:
    """Review 1..16 exact strings; return immutable metadata ONLY.

    No untrusted note content, rejected host, credential-like value or detailed
    rejection reason is returned. False negatives remain possible: REVIEW_ONLY
    NEVER means safe to publish, let alone authorization to execute.
    """
    if type(notes) is not tuple or not (1 <= len(notes) <= _MAX_NOTES):
        return _hold()
    total = 0
    for note in notes:
        if type(note) is not str or not note.strip():
            return _hold()
        try:
            raw = note.encode("ascii", "strict")
        except UnicodeError:
            return _hold()
        total += len(raw)
        if len(raw) > _MAX_NOTE_BYTES or total > _MAX_TOTAL_BYTES:
            return _hold()
        if not _ALLOWED_CHARS.fullmatch(note) or "\r" in note or "\x00" in note:
            return _hold()
        if _SECRET_HINT.search(note) or _IPV4_SHAPE.search(note) or _IPV6_SHAPE.search(note):
            return _hold()
        hosts = _DOTTED_NAME.findall(note)
        if not hosts or any(_RESERVED_HOST.fullmatch(host) is None for host in hosts):
            return _hold()
        # Dotted punctuation cannot be used to smuggle a host split across tokens.
        if ".." in note or ". " in note and re.search(r"\.[ ]+[A-Za-z0-9-]+\.", note):
            return _hold()
    return DisclosureVerdict("REVIEW_ONLY", _REVIEW, len(notes))
