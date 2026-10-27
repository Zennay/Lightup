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

    def __post_init__(self) -> None:
        # Even manually constructed receipts cannot describe release authority.
        # A caller can still fabricate REVIEW_ONLY; never treat it as consent.
        if type(self.status) is not str or self.status not in {"HOLD", "REVIEW_ONLY"}:
            raise ValueError("only non-authorizing review statuses are supported")
        for flag in (
            self.grants_authority,
            self.can_issue_permit,
            self.can_dispatch,
            self.can_release,
        ):
            if type(flag) is not bool or flag is not False:
                raise ValueError("review receipt must remain non-authorizing")


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


def review_lab_reference_history(
    prior_references: object, proposed_references: object
) -> LabReferenceReview:
    """Pure, bounded *fictional* within-window replay-collision review.

    The prior history must be an exact tuple of 0..64 unique canonical refs;
    proposals must be an exact tuple of 1..64 unique canonical refs. No
    proposed reference may appear in the prior window. This makes no claims
    about durable/global history, actual operator identity or authorization.
    Both inputs are reviewed atomically and remain unchanged; never coerce
    caller-defined collection/string subclasses or consult external state.
    """
    if type(prior_references) is not tuple:
        return _HOLD
    if len(prior_references) > _MAX_ITEMS:
        return _HOLD
    if prior_references and review_lab_reference_batch(prior_references) is not _REVIEW_ONLY:
        return _HOLD
    if review_lab_reference_batch(proposed_references) is not _REVIEW_ONLY:
        return _HOLD
    # Exact immutable tuple + exact built-in strings have been validated.
    # Never pass untrusted custom __hash__ or __eq__ into this comparison.
    prior = set(prior_references)
    if any(reference in prior for reference in proposed_references):
        return _HOLD
    return _REVIEW_ONLY
