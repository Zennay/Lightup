"""Opt-in, all-or-nothing preview of strict scope for a bounded target batch.

A scope *preview* is NOT an authorization grant, permit, scan, execution,
consent verification, or activation. It never performs DNS/network I/O and
is not wired into any default endpoint.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

from .models import Authorization, Target
from .scope import ScopeDecision, ScopeReason
from .strict_target_scope_optin import StrictTargetScopePolicy

_MAX_ITEMS = 64
_MAX_LABELS = 16
_MAX_RAW_TARGET = 2048
_MAX_IDENT = 128
_ALLOWED_REASONS = frozenset((
    ScopeReason.LOOPBACK, ScopeReason.PRIVATE_LAB,
    ScopeReason.EXPLICIT_HOST, ScopeReason.EXPLICIT_NETWORK,
))
_IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


class ScopeBatchRejected(ValueError):
    """Constant non-echoing refusal; do not serialize raw target/consent."""


@dataclass(frozen=True, slots=True)
class ScopeBatchPreview:
    """Aggregated non-authoritative plan receipt, never passed to a gate."""

    target_count: int
    reason_counts: tuple[tuple[str, int], ...]
    grant_issued: bool = field(default=False, init=False)
    execution_enabled: bool = field(default=False, init=False)


def _canonical_authorization(auth: Authorization | None) -> bool:
    if auth is None:
        return True
    if type(auth) is not Authorization:
        return False
    for value in (auth.owner, auth.reference):
        if type(value) is not str or len(value) > _MAX_IDENT:
            return False
        if _IDENTITY_RE.fullmatch(value) is None:
            return False
    for value in (auth.valid_from, auth.valid_until):
        if value is None:
            continue
        # Exact fixed-offset timezone avoids caller-controlled tzinfo hooks.
        if type(value) is not datetime or type(value.tzinfo) is not timezone:
            return False
    if (auth.valid_from is not None and auth.valid_until is not None
            and auth.valid_from > auth.valid_until):
        return False
    return True


def preview_scope_batch(
    policy: StrictTargetScopePolicy,
    targets: tuple[Target, ...],
) -> ScopeBatchPreview:
    """Check an entire immutable batch, refuse atomically on any invalid item.

    The returned receipt gives only aggregate category counts. It cannot
    confer current or future execution authority; original ScopePolicy
    continues to own scope and explicit-grant decisions.
    """
    if type(policy) is not StrictTargetScopePolicy:
        raise ScopeBatchRejected("scope batch refused")
    if type(targets) is not tuple or not 1 <= len(targets) <= _MAX_ITEMS:
        raise ScopeBatchRejected("scope batch refused")

    # Validate *every* outer/nested record before performing *any* decision,
    # preventing late-invalid input from reaching source grant callbacks.
    for target in targets:
        if type(target) is not Target:
            raise ScopeBatchRejected("scope batch refused")
        if (type(target.value) is not str or not target.value
                or len(target.value) > _MAX_RAW_TARGET):
            raise ScopeBatchRejected("scope batch refused")
        if type(target.labels) is not tuple or len(target.labels) > _MAX_LABELS:
            raise ScopeBatchRejected("scope batch refused")
        if any(type(label) is not str or _LABEL_RE.fullmatch(label) is None
               for label in target.labels):
            raise ScopeBatchRejected("scope batch refused")
        if not _canonical_authorization(target.authorization):
            raise ScopeBatchRejected("scope batch refused")

    # No partial result can escape: all decisions must agree on safe authority.
    reasons: Counter[str] = Counter()
    seen_hosts: set[str] = set()
    try:
        for target in targets:
            decision = policy.decide(target)
            if (type(decision) is not ScopeDecision
                    or decision.allowed is not True
                    or type(decision.reason) is not ScopeReason
                    or decision.reason not in _ALLOWED_REASONS
                    or type(decision.normalized_host) is not str
                    or not decision.normalized_host):
                raise ScopeBatchRejected("scope batch refused")
            if decision.normalized_host in seen_hosts:
                raise ScopeBatchRejected("scope batch refused")
            seen_hosts.add(decision.normalized_host)
            reasons[decision.reason.value] += 1
    except Exception as exc:
        # Fail closed with no original target, host, reference or exception
        # details in the caller-visible refusal.
        raise ScopeBatchRejected("scope batch refused") from None

    return ScopeBatchPreview(
        target_count=len(targets),
        reason_counts=tuple(sorted(reasons.items())),
    )
