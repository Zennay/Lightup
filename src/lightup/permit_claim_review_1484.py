"""Unwired, offline-only quarantine of fabricated legacy ExecutionPermit claims.

No source attestation, real-target admission, grants, handlers or release.
'REVIEW_ONLY' never conveys authorization.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from .activation import ActivationMode, ExecutionPermit

ID = re.compile(r"[A-Za-z0-9_-]{32}", re.ASCII)
CAP = re.compile(r"[a-z][a-z0-9_.:-]{0,63}", re.ASCII)
REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", re.ASCII)
FAKE_HOST = re.compile(r"(?:[a-z0-9-]{1,63}\.)+example\.test", re.ASCII)

@dataclass(frozen=True)
class PermitClaimReview:
    status: str
    reason_code: str
    inspected: int
    execution_allowed: bool = False
    release_allowed: bool = False

def _hold(reason: str) -> PermitClaimReview:
    return PermitClaimReview("HOLD", reason, 0)

def _canonical(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None

def _fake_target(value: object) -> bool:
    return type(value) is str and (
        value in ("localhost", "127.0.0.1")
        or FAKE_HOST.fullmatch(value) is not None
    )

def review_fictional_permit_claim_batch(
    claims: object, *, review_cutoff: object
) -> PermitClaimReview:
    """Bounded synthetic-only review; never an execution or release decision.

    Duplicate IDs are checked within this tuple only. A caller-controlled
    batch cannot prove original issuance, cross-batch replay or revocation.
    """
    if type(review_cutoff) is not datetime or review_cutoff.tzinfo is not timezone.utc:
        return _hold("invalid_cutoff")
    if type(claims) is not tuple or not 1 <= len(claims) <= 64:
        return _hold("invalid_batch")
    seen: set[str] = set()
    for claim in claims:
        if type(claim) is not ExecutionPermit:
            return _hold("invalid_claim")
        if not _canonical(claim.permit_id, ID):
            return _hold("invalid_claim")
        if not _fake_target(claim.target):
            return _hold("invalid_claim")
        if not _canonical(claim.capability_id, CAP):
            return _hold("invalid_claim")
        if type(claim.mode) is not ActivationMode:
            return _hold("invalid_claim")
        if claim.mode not in (ActivationMode.LAB_ONLY, ActivationMode.AUTHORIZED):
            return _hold("invalid_claim")
        if not _canonical(claim.activation_reference, REF):
            return _hold("invalid_claim")
        if type(claim.issued_at) is not datetime or claim.issued_at.tzinfo is not timezone.utc:
            return _hold("invalid_claim")
        if claim.issued_at > review_cutoff:
            return _hold("future_claim")
        if claim.permit_id in seen:
            return _hold("duplicate_in_batch")
        seen.add(claim.permit_id)
    return PermitClaimReview("REVIEW_ONLY", "fictional_shape_only", len(claims))
