"""Unwired, offline-only review of synthetic tool-handler admission shapes.

This is NOT a validator attached to ToolRegistry and cannot issue authority.
No handler is ever invoked; a REVIEW_ONLY result must never be used as consent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from inspect import CO_ASYNC_GENERATOR, CO_COROUTINE, CO_GENERATOR, CO_VARARGS, CO_VARKEYWORDS
from types import FunctionType
import re

_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", flags=re.ASCII)
_UNSAFE_FLAGS = CO_ASYNC_GENERATOR | CO_COROUTINE | CO_GENERATOR | CO_VARARGS | CO_VARKEYWORDS


@dataclass(frozen=True, slots=True)
class HandlerAdmissionReview:
    status: str
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def review_handlers(records: object) -> HandlerAdmissionReview:
    """Review 1..32 EXACT synthetic (identifier, plain_function) pairs.

    All values are caller-owned fictional observations. A valid shape returns
    REVIEW_ONLY, never approval to register, execute or contact a target.
    """
    if type(records) is not tuple or not 1 <= len(records) <= 32:
        return HandlerAdmissionReview("HOLD")
    seen: set[str] = set()
    for row in records:
        if type(row) is not tuple or len(row) != 2:
            return HandlerAdmissionReview("HOLD")
        identifier, handler = row
        if (type(identifier) is not str or _NAME.fullmatch(identifier) is None
                or identifier in seen):
            return HandlerAdmissionReview("HOLD")
        seen.add(identifier)
        if type(handler) is not FunctionType:
            return HandlerAdmissionReview("HOLD")
        code = handler.__code__
        if (code.co_posonlyargcount != 0 or code.co_argcount != 2
                or code.co_kwonlyargcount != 0 or code.co_flags & _UNSAFE_FLAGS
                or handler.__defaults__ is not None
                or handler.__kwdefaults__ is not None
                or handler.__closure__ is not None):
            return HandlerAdmissionReview("HOLD")
    return HandlerAdmissionReview("REVIEW_ONLY")
