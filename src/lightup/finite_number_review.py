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
