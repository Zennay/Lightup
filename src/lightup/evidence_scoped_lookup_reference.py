"""UNINSTALLED opt-in reference for prelookup evidence ID + current-scope checks.

This is an integration *candidate* for the original #1075 StateStore owner.
The injected check is NOT itself an authorization service: production callers
must bind it to trusted authenticated tenant, grant and revocation state.
Nothing in this module is wired into existing routes, runtimes or workers.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable

from .evidence_id_admission import canonical_evidence_id
from .state import EvidenceRecord, StateStore

_DENIED = "evidence lookup denied"
_UNAVAILABLE = "evidence lookup unavailable"


def _checked_current_permission(
    checker: Callable[[str, str, str], bool],
    run_id: str,
    capability_id: str,
    evidence_id: str,
) -> None:
    """Fail closed on errors and non-exact boolean authorization responses."""
    try:
        approved = checker(run_id, capability_id, evidence_id)
    except Exception:
        # Never disclose provider exception content, tenant details or IDs.
        raise PermissionError(_DENIED) from None
    if approved is not True or type(approved) is not bool:
        raise PermissionError(_DENIED)


def get_evidence_with_current_scope_reference(
    store: StateStore,
    evidence_id: object,
    *,
    trusted_run_id: object,
    trusted_capability_id: object,
    check_current_permission: Callable[[str, str, str], bool],
) -> EvidenceRecord:
    """Return a scoped evidence row only after strict opt-in prelookup checks.

    The reference checker is called BEFORE the read, and AGAIN after the
    row is decoded. This does not make checking authorization atomic with a
    concurrent revocation, prove caller authentication, or replace the actual
    trusted source owner's installed tenant/capability grant admission.
    """
    canonical = canonical_evidence_id(evidence_id)
    if canonical is None:
        raise ValueError("noncanonical evidence identifier")
    if (
        type(store) is not StateStore
        or canonical_evidence_id(trusted_run_id) is None
        or type(trusted_capability_id) is not str
        or not 1 <= len(trusted_capability_id) <= 128
        or not trusted_capability_id.isprintable()
        or trusted_capability_id != trusted_capability_id.strip()
        or not callable(check_current_permission)
    ):
        raise PermissionError(_DENIED)

    # These are *reference* labels. The injected checker MUST independently
    # resolve authenticated current tenant/ownership/operator grant context;
    # matching requester-provided labels alone never constitutes authority.
    _checked_current_permission(
        check_current_permission, trusted_run_id, trusted_capability_id, canonical
    )
    try:
        record = store.get_evidence(canonical)
    except (LookupError, ValueError, TypeError, sqlite3.Error):
        raise LookupError(_UNAVAILABLE) from None
    if (
        type(record) is not EvidenceRecord
        or record.evidence_id != canonical
        or record.run_id != trusted_run_id
        or record.capability_id != trusted_capability_id
    ):
        raise PermissionError(_DENIED)
    # Fail closed if a source owner revokes access during the SQLite read.
    # Production still needs trusted atomic action-time grant enforcement.
    _checked_current_permission(
        check_current_permission, trusted_run_id, trusted_capability_id, canonical
    )
    return record
