"""Pure opt-in finite NUMBER admission reference for issue #1143.

A call site must explicitly invoke this *before* ToolExecutor.execute. The
production executor does not currently import this helper; source-owner
integration and independent authorization gates remain necessary.

No target I/O, handler, resolver, permit, or release authority is provided.
"""
from __future__ import annotations

import math
import re

_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_MAX_FIELDS = 32
_MAX_INT_BITS = 4096  # Bound workload without coercing large exact integers to float.


def snapshot_finite_number_arguments(entries: object) -> tuple[tuple[str, int | float], ...]:
    """Atomically accept exact built-in finite numbers, never Python subtypes.

    Input: an exact tuple of 1..32 (canonical-name, value) pairs. Invalid
    batches raise an opaque ValueError before returning *any* partial entries.
    For exact ints, never coerce to float: finite integers up to 4096 bits
    preserve precision; larger magnitudes fail closed before downstream work.
    """
    if type(entries) is not tuple or not 1 <= len(entries) <= _MAX_FIELDS:
        raise ValueError("noncanonical finite number batch")
    seen: set[str] = set()
    checked: list[tuple[str, int | float]] = []
    for pair in entries:
        if type(pair) is not tuple or len(pair) != 2:
            raise ValueError("noncanonical finite number batch")
        name, value = pair
        if (type(name) is not str or _NAME.fullmatch(name) is None
                or name in seen):
            raise ValueError("noncanonical finite number batch")
        if type(value) is int:
            if value.bit_length() > _MAX_INT_BITS:
                raise ValueError("noncanonical finite number batch")
        elif type(value) is float and math.isfinite(value):
            pass
        else:
            raise ValueError("noncanonical finite number batch")
        seen.add(name)
        checked.append((name, value))
    return tuple(sorted(checked))


def review_finite_number_arguments(entries: object) -> dict[str, object]:
    """Privacy-minimal machine receipt; never identifies a real authorized run."""
    try:
        accepted = snapshot_finite_number_arguments(entries)
    except (ValueError, OverflowError, TypeError, RecursionError):
        accepted = ()
    return {
        "status": "REVIEW_ONLY" if accepted else "HOLD",
        "reason": "finite_builtin_numbers_only" if accepted else "invalid_finite_number_batch",
        "checked_count": len(accepted),
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "merge_approved": False,
        "release_approved": False,
    }
