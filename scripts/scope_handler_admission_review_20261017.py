"""Unwired, offline-only review of synthetic tool-handler admission shapes.

This is NOT a validator attached to ToolRegistry and cannot issue authority.
No handler is ever invoked; a REVIEW_ONLY result must never be used as consent.
"""
from __future__ import annotations

from inspect import CO_ASYNC_GENERATOR, CO_COROUTINE, CO_GENERATOR, CO_VARARGS, CO_VARKEYWORDS
from types import FunctionType
import re

_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\\Z", flags=re.ASCII)
_UNSAFE_FLAGS = CO_ASYNC_GENERATOR | CO_COROUTINE | CO_GENERATOR | CO_VARARGS | CO_VARKEYWORDS


class HandlerAdmissionReview(tuple):
    """Immutable single-status observation. It does not grant authority.

    A tuple has no writable slots or dictionary. Even object.__setattr__
    cannot flip one of the four false authority properties.
    This is ordinary in-process misuse resistance, NOT a security principal.
    """
    __slots__ = ()

    def __new__(cls, status: str) -> HandlerAdmissionReview:
        if cls is not HandlerAdmissionReview or type(status) is not str or status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid offline review status")
        return tuple.__new__(cls, (status,))

    @property
    def status(self) -> str:
        return self[0]

    @property
    def authorized(self) -> bool:
        return False

    @property
    def consent_verified(self) -> bool:
        return False

    @property
    def dispatch_allowed(self) -> bool:
        return False

    @property
    def release_allowed(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"HandlerAdmissionReview(status={self.status!r})"

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
