"""Atomic fictional LAB capability cohort review (#1511).

An entirely offline, UNWIRED advisory. A caller-created tuple of capability
identities is NOT an authenticated registry, scope decision or client consent.
No caller receives a permit, dispatch token, or release authority.
"""
from __future__ import annotations

from .fictional_lab_capability_review_1511 import (
    LabCapabilityReview1511,
    _canonical_capability_id,
)

_MAX_COHORT = 64


def review_fictional_lab_capability_cohort_1511(
    requested: object, fictional_allowlist: object
) -> LabCapabilityReview1511:
    """All-or-HOLD for 1..64 distinct exact-builtin fictional request IDs.

    No per-ID result is exposed: a malformed/missing/duplicated identity
    makes the entire batch HOLD, never a misleading partially accepted set.
    REVIEW_ONLY means input-consistent *fiction*, NOT authority.
    """
    if type(requested) is not tuple or type(fictional_allowlist) is not tuple:
        return LabCapabilityReview1511("HOLD")
    if not (1 <= len(requested) <= _MAX_COHORT):
        return LabCapabilityReview1511("HOLD")
    if not (1 <= len(fictional_allowlist) <= _MAX_COHORT):
        return LabCapabilityReview1511("HOLD")
    # Do not call custom __eq__, __hash__, __str__, __iter__, __contains__,
    # or item accessors on non-builtin values. Validate every member first.
    if any(not _canonical_capability_id(item) for item in requested):
        return LabCapabilityReview1511("HOLD")
    if any(not _canonical_capability_id(item) for item in fictional_allowlist):
        return LabCapabilityReview1511("HOLD")
    if len(set(requested)) != len(requested):
        return LabCapabilityReview1511("HOLD")
    if len(set(fictional_allowlist)) != len(fictional_allowlist):
        return LabCapabilityReview1511("HOLD")
    allowlisted = frozenset(fictional_allowlist)
    if any(item not in allowlisted for item in requested):
        return LabCapabilityReview1511("HOLD")
    return LabCapabilityReview1511("REVIEW_ONLY")
