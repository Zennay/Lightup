"""Fictional LAB_ONLY capability identity review for issue #1511.

This module is deliberately UNWIRED. A caller-provided list is NOT a trusted
tool registry. REVIEW_ONLY is not a permit, consent, scope, or release decision.
No production admission handler imports this module.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_CAPABILITY_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", re.ASCII)
_MAX_ID_LENGTH = 64
_MAX_IDS = 64


@dataclass(frozen=True, slots=True)
class LabCapabilityReview1511:
    status: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


_HOLD = LabCapabilityReview1511("HOLD")
_REVIEW_ONLY = LabCapabilityReview1511("REVIEW_ONLY")


def _canonical_capability_id(value: object) -> bool:
    # Exact type, not isinstance: never invoke caller-controlled equality,
    # formatting, __str__, regex conversion, or attribute access.
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_ID_LENGTH
        and _CAPABILITY_ID.fullmatch(value) is not None
    )


def review_fictional_lab_capability_1511(
    requested: object, fictional_allowlist: object
) -> LabCapabilityReview1511:
    """Strict in-memory *advisory* check; never grant LAB_ONLY execution.

    Requires an exact tuple of canonical builtin strings.  A tuple subclass,
    string subclass, duplicated alias, absent ID, or any malformed value
    always results in generic HOLD. Only a locally consistent *fictional*
    snapshot yields REVIEW_ONLY, with all authority fields permanently false.

    This must not be used as an authority or registry/consent attestation.
    """
    if type(fictional_allowlist) is not tuple:
        return _HOLD
    if not (1 <= len(fictional_allowlist) <= _MAX_IDS):
        return _HOLD
    if not _canonical_capability_id(requested):
        return _HOLD
    # Builtins-only path; avoid touching arbitrary caller-supplied objects.
    if any(not _canonical_capability_id(item) for item in fictional_allowlist):
        return _HOLD
    if len(set(fictional_allowlist)) != len(fictional_allowlist):
        return _HOLD
    if requested not in fictional_allowlist:
        return _HOLD
    return _REVIEW_ONLY
