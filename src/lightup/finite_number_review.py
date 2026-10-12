"""Optional numeric argument integrity reference for issue #1143.

NOT wired to ToolExecutor, ScopePolicy or any network/authorization path.
Passing this shape review is not a grant, authorization, or dispatch decision.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any


class FiniteNumberRefused(ValueError):
    """A caller-supplied value is not an exact, finite built-in number."""


@dataclass(frozen=True)
class FiniteNumberReview:
    """Purely structural observation; deliberately cannot authorize execution."""

    kind: str

    def __bool__(self) -> bool:
        raise TypeError("numeric integrity review is not execution authorization")


def review_finite_number(value: Any) -> FiniteNumberReview:
    """Fail closed for non-finite floats and noncanonical runtime types.

    Built-in arbitrary-precision ints are finite without float conversion.
    Never call custom numeric methods (including __float__, __int__, __repr__,
    equality or ordering) on an untrusted object; diagnostics cannot echo it.
    This is an uninstalled, non-authorizing reference contract only.
    """
    if type(value) is int:
        return FiniteNumberReview("integer")
    if type(value) is float and math.isfinite(value):
        return FiniteNumberReview("float")
    raise FiniteNumberRefused("NUMBER requires an exact finite int or float")


# A review batch is deliberately small: it is not an arbitrary stream, and
# no downstream component should treat a successful shape check as consent.
MAX_OFFLINE_NUMBER_BATCH = 64


@dataclass(frozen=True)
class FiniteNumberBatchReview:
    """Atomic structural observations only, never an authorization permit."""

    items: tuple[FiniteNumberReview, ...]

    def __bool__(self) -> bool:
        raise TypeError("numeric batch integrity review is not execution authorization")


def review_finite_number_batch(values: object) -> FiniteNumberBatchReview:
    """Inspect an exact, bounded tuple of NUMBER values atomically.

    On any invalid member the caller receives only the same generic exception
    as the scalar reviewer, not a successful partial result or input contents.
    An exact-tuple check prevents custom iteration/indexing code from running.
    No ToolExecutor, policy, evidence ledger, network or authorization I/O.
    """
    if type(values) is not tuple or len(values) > MAX_OFFLINE_NUMBER_BATCH:
        raise FiniteNumberRefused("NUMBER batch requires a bounded exact tuple")
    return FiniteNumberBatchReview(tuple(review_finite_number(v) for v in values))
