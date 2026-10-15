"""Atomic, bounded offline revocation metadata batch triage (#737).

Non-authorizing plan/lab review ONLY. No network, file I/O, state mutation,
source-of-truth revocation, or live grant decisions.
"""
from __future__ import annotations

from dataclasses import dataclass

from scripts.scope_737_revocation_metadata_review import review_revocation_metadata


_FIELDS = frozenset({"revoked_at", "revoked_by", "revocation_reason"})
_MAX_BATCH = 64
_CLASSES = ("inconsistent", "revocation_recorded", "no_revocation_claim")


@dataclass(frozen=True)
class RevocationBatchReview:
    decision: str
    result: str
    classifications: tuple[str, ...]
    class_counts: tuple[tuple[str, int], ...]
    reason_codes: tuple[str, ...]
    can_authorize: bool = False
    can_dispatch: bool = False
    can_release: bool = False


def _invalid(reason: str) -> RevocationBatchReview:
    return RevocationBatchReview(
        decision="HOLD",
        result="invalid_batch",
        classifications=(),
        class_counts=(),
        reason_codes=(reason,),
    )


def review_revocation_batch(records: object) -> RevocationBatchReview:
    """No partial results: reject noncanonical/missing/oversized records as a unit.

    Require an exact built-in tuple (1..64) of exact built-in dicts with
    exactly the three known exact built-in string keys. Values are reviewed
    by the separate #737 pure function. No input object is stringified,
    serialized, transformed, executed, or returned in the output.
    """
    if type(records) is not tuple:
        return _invalid("noncanonical_batch_container")
    if not 1 <= len(records) <= _MAX_BATCH:
        return _invalid("batch_size_out_of_bounds")

    for item in records:
        if type(item) is not dict:
            return _invalid("noncanonical_batch_item")
        if len(item) != len(_FIELDS):
            return _invalid("invalid_batch_schema")
        if any(type(k) is not str for k in item.keys()):
            return _invalid("noncanonical_batch_key")
        if frozenset(item.keys()) != _FIELDS:
            return _invalid("invalid_batch_schema")

    classes = tuple(
        review_revocation_metadata(
            revoked_at=item["revoked_at"],
            revoked_by=item["revoked_by"],
            revocation_reason=item["revocation_reason"],
        ).classification
        for item in records
    )
    return RevocationBatchReview(
        decision="HOLD",
        result="review_only",
        classifications=classes,
        class_counts=tuple((name, classes.count(name)) for name in _CLASSES),
        reason_codes=("independent_authorization_verification_required",),
    )
