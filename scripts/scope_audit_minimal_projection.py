"""Fail-closed, offline projection of scope decision audit metadata.

This module does not grant authorization, sign receipts, or trigger execution.
It intentionally does not accept evidence payloads, credentials or raw target URLs.
"""
from __future__ import annotations

import json
import re
from typing import Any

_FIELDS = ("decision_id", "tenant_id", "run_id", "grant_id", "outcome", "reason_code")
_MAX_LENGTH = 128
_OUTCOMES = frozenset({"allow", "deny"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*\\Z")
_REASON = re.compile(r"[A-Za-z][A-Za-z0-9_]*\\Z")


def project_scope_decision(value: Any) -> dict[str, str]:
    """Return a minimal audit index, rejecting unexpected and malformed input."""
    if type(value) is not dict or set(value) != set(_FIELDS):
        raise ValueError("noncanonical scope decision envelope")
    projected = {}
    for field in _FIELDS:
        raw = value[field]
        if type(raw) is not str or not raw or len(raw) > _MAX_LENGTH:
            raise ValueError("invalid scope decision field")
        if field not in ("outcome", "reason_code") and _IDENTIFIER.fullmatch(raw) is None:
            raise ValueError("invalid scope decision identifier")
        if any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in raw):
            raise ValueError("invalid scope decision characters")
        projected[field] = raw
    if projected["outcome"] not in _OUTCOMES:
        raise ValueError("invalid scope decision outcome")
    if _REASON.fullmatch(projected["reason_code"]) is None:
        raise ValueError("invalid scope decision reason")
    return projected


def encode_scope_decision(value: Any) -> str:
    """Produce stable canonical JSON without inadvertently serializing extras."""
    return json.dumps(project_scope_decision(value), sort_keys=True, separators=(",", ":"))
