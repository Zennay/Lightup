"""UNINSTALLED bounded evidence-byte digest comparison reference (#1075).

This does not retrieve, distribute or authenticate evidence bytes. Callers
must provide their own already-held bytes and a genuinely trusted current
permission checker. A stored hash is NOT a signature or issuer attestation.
"""
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from .evidence_scoped_lookup_reference import (
    _checked_current_permission,
    get_evidence_with_current_scope_reference,
)
from .state import EvidenceRecord, StateStore

_MAX_BYTES = 8 * 1024 * 1024
_LOWER_HEX = frozenset("0123456789abcdef")
_FAILURE = "evidence payload integrity unavailable"


def verify_scoped_evidence_payload_reference(
    store: StateStore,
    evidence_id: object,
    payload: object,
    *,
    trusted_run_id: object,
    trusted_capability_id: object,
    check_current_permission: Callable[[str, str, str], bool],
    max_payload_bytes: int = _MAX_BYTES,
) -> EvidenceRecord:
    """Reference-check explicit bounded bytes against the persisted SHA-256.

    The existing optional scoped reader checks caller-injected permissions
    before and after the store lookup. Once hashing finishes, perform a THIRD
    injected current check immediately before yielding the record, including
    the potential long hashing interval. This is NOT atomic revocation.
    """
    if type(max_payload_bytes) is not int or not 1 <= max_payload_bytes <= _MAX_BYTES:
        raise ValueError("invalid evidence payload budget")
    if type(payload) is not bytes or len(payload) > max_payload_bytes:
        raise ValueError("invalid bounded evidence payload")

    record = get_evidence_with_current_scope_reference(
        store,
        evidence_id,
        trusted_run_id=trusted_run_id,
        trusted_capability_id=trusted_capability_id,
        check_current_permission=check_current_permission,
    )
    expected = record.sha256
    if (
        type(expected) is not str
        or len(expected) != 64
        or any(char not in _LOWER_HEX for char in expected)
    ):
        raise ValueError(_FAILURE)
    actual = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError(_FAILURE)
    # This callback is untrusted unless an upstream authenticated operator,
    # tenant and current grant resolver supplies the actual implementation.
    _checked_current_permission(
        check_current_permission,
        trusted_run_id,
        trusted_capability_id,
        record.evidence_id,
    )
    return record
