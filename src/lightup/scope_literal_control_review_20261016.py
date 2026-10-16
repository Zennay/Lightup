"""Offline review of exact, unmodified fictional scope strings.

This module is deliberately NOT connected to ScopePolicy, ActivationGate,
ExecutionPolicy, a registry, or a handler. REVIEW_ONLY is never permission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

_MAX_ITEMS = 64
_MAX_CHARS = 512


@dataclass(frozen=True, slots=True)
class LiteralReview:
    status: Literal["HOLD", "REVIEW_ONLY"]
    authorized: bool = field(init=False, default=False)
    consent_verified: bool = field(init=False, default=False)
    dispatch_allowed: bool = field(init=False, default=False)
    release_allowed: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        # A Literal type hint alone provides no runtime validation. Invalid
        # states cannot be misrepresented as a review outcome.
        if type(self.status) is not str or self.status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid offline review state")


def review_literals(candidates: object) -> LiteralReview:
    """Reject lossy/control-bearing review strings, without parsing authority.

    Valid strings only qualify for *offline human comparison*. They must NEVER
    be interpreted as approved hosts, grants, consent, or dispatch targets.
    """
    if type(candidates) is not tuple or not 1 <= len(candidates) <= _MAX_ITEMS:
        return LiteralReview("HOLD")
    seen: set[str] = set()
    for value in candidates:
        if type(value) is not str or not 1 <= len(value) <= _MAX_CHARS:
            return LiteralReview("HOLD")
        # No parser or Unicode normalization can silently erase or replace an
        # arbitrary control/format character in a copied scope review packet.
        # Visible ASCII is the *input integrity* bar, NOT target authorization.
        if any(not 0x21 <= ord(ch) <= 0x7E for ch in value):
            return LiteralReview("HOLD")
        # Conservative byte-exact HOLD for potential later URL/backslash
        # decoding; this is NOT a hostname validator or grant decision.
        if "%" in value or "\\" in value:
            return LiteralReview("HOLD")
        if value in seen:
            return LiteralReview("HOLD")
        seen.add(value)
    return LiteralReview("REVIEW_ONLY")
