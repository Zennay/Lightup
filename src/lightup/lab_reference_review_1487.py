"""Conservative, non-authorizing review of *fictional* LAB references (#1487).

This standalone helper is NOT imported by ActivationGate or any executor.
A REVIEW_ONLY result does not identify a real session, attest ownership,
verify consent, issue a permit, or permit a lab action. Fail closed to HOLD.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_MAX_ITEMS = 64
_MAX_LENGTH = 128
_MIN_LENGTH = 8
# Conservative review subset, *not* an activation-reference protocol.
# Require a LAB- prefix, uppercase ASCII alphanumeric segments and literal
# hyphen separators. In particular, no URL/path, dots, Unicode or controls.
_REVIEW_SYNTAX = re.compile(r"LAB-[A-Z0-9]+(?:-[A-Z0-9]+)*", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class LabReferenceReview:
    status: str
    grants_authority: bool = False
    can_issue_permit: bool = False
    can_dispatch: bool = False
    can_release: bool = False


_HOLD = LabReferenceReview("HOLD")
_REVIEW_ONLY = LabReferenceReview("REVIEW_ONLY")


def review_lab_reference_batch(references: object) -> LabReferenceReview:
    """Review a bounded *exact tuple* without inspecting external state.

    Enforces syntactic uniqueness of references within this one fictional
    batch, not global uniqueness, operator authentication, or provenance.
    String subclasses, custom iterable implementations and invalid entries
    are never coerced or evaluated for truthiness.
    """
    if type(references) is not tuple:
        return _HOLD
    if not (1 <= len(references) <= _MAX_ITEMS):
        return _HOLD

    seen: set[str] = set()
    for reference in references:
        if type(reference) is not str:
            return _HOLD
        if not (_MIN_LENGTH <= len(reference) <= _MAX_LENGTH):
            return _HOLD
        if _REVIEW_SYNTAX.fullmatch(reference) is None:
            return _HOLD
        if reference in seen:
            return _HOLD
        seen.add(reference)
    return _REVIEW_ONLY
