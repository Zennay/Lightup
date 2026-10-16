"""Synthetic operator-facing scope notice; UNWIRED, non-authorizing.

Do not connect this to production activation, policy, grants or dispatch.
All assets are deliberately reserved `.example.test` examples.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

_ASSET_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_CAPABILITY = re.compile(r"[a-z][a-z0-9_-]{1,31}\Z", re.ASCII)
_MAX_PROPOSALS = 32
_MAX_NOTICE_CHARS = 8192

_HOLD = (
    "HOLD — NOT AUTHORIZED. Synthetic scope notice cannot be generated "
    "from these inputs. Nothing has been approved or dispatched."
)


@dataclass(frozen=True, slots=True)
class ScopeProposal:
    """Caller-supplied fictional proposal, NOT verified authorization."""

    asset: str
    capability: str
    risk: int
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class ScopeNotice:
    status: str
    text: str
    reviewed: int
    elevated_risk: bool
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _invalid() -> ScopeNotice:
    # Never echo malformed input, even in a review-only preview.
    return ScopeNotice("HOLD", _HOLD, 0, False)


def _canonical_instant(value: object) -> bool:
    # No subclassed datetime, floating-local clocks, folds, or ISO parsing.
    return (
        type(value) is datetime
        and value.tzinfo is timezone.utc
        and value.fold == 0
        and value.microsecond == 0
        and 2024 <= value.year <= 2100
    )


def _fictional_asset(value: object) -> bool:
    if type(value) is not str or len(value) > 253:
        return False
    if not value.endswith(".example.test"):
        return False
    labels = value.split(".")
    if len(labels) < 3:
        return False
    if any(
        not (1 <= len(label) <= 63)
        or _ASSET_LABEL.fullmatch(label) is None
        or label.startswith("xn--")
        for label in labels
    ):
        return False
    return True


def _valid_proposal(value: object, at: datetime) -> bool:
    if type(value) is not ScopeProposal:
        return False
    if not _fictional_asset(value.asset):
        return False
    if type(value.capability) is not str or _CAPABILITY.fullmatch(value.capability) is None:
        return False
    if type(value.risk) is not int or not 1 <= value.risk <= 5:
        return False
    if not (_canonical_instant(value.valid_from) and _canonical_instant(value.valid_until)):
        return False
    if not (value.valid_from <= at < value.valid_until):
        return False
    # A bounded proposal cannot silently imply indefinite authorization.
    return (value.valid_until - value.valid_from).total_seconds() <= 90 * 86400


def render_scope_notice(
    proposals: tuple[ScopeProposal, ...],
    *,
    review_at: datetime,
) -> ScopeNotice:
    """Produce a bounded HUMAN REVIEW preview, never proof of permission.

    Invalid/noncanonical/coincident entries reject the entire tuple. This
    function never reads a trusted consent store or evaluates a real target.
    """
    if not _canonical_instant(review_at):
        return _invalid()
    if type(proposals) is not tuple or not (1 <= len(proposals) <= _MAX_PROPOSALS):
        return _invalid()
    if not all(_valid_proposal(p, review_at) for p in proposals):
        return _invalid()

    # Even windows that do not overlap may not reuse an asset/capability pair
    # in a single notice: the human must review separate proposals separately.
    keys = tuple((p.asset, p.capability) for p in proposals)
    if len(set(keys)) != len(keys):
        return _invalid()

    ordered = sorted(proposals, key=lambda p: (p.asset, p.capability))
    lines = [
        "NOT AUTHORIZED — SYNTHETIC SCOPE REVIEW ONLY",
        "No client consent, operator identity, approval or execution authority verified.",
        f"Fictional proposal count: {len(ordered)}",
        f"Review timestamp (UTC): {review_at.isoformat().replace('+00:00', 'Z')}",
        "",
        "Proposed asset | capability | risk | start UTC | end UTC:",
    ]
    for entry in ordered:
        start = entry.valid_from.isoformat().replace("+00:00", "Z")
        end = entry.valid_until.isoformat().replace("+00:00", "Z")
        lines.append(f"- {entry.asset} | {entry.capability} | {entry.risk}/5 | {start} | {end}")

    high_risk = any(p.risk >= 4 for p in ordered)
    lines.extend((
        "",
        "Risk escalation: independent step-up and human scrutiny required."
        if high_risk else "Risk escalation: risk scores still need independent human review.",
        "This is NOT a grant, consent record, dispatch ticket or release approval.",
        "No real assets, scans, tools, data collection or production changes permitted.",
    ))
    report = "\n".join(lines)
    if len(report) > _MAX_NOTICE_CHARS:
        return _invalid()
    return ScopeNotice("REVIEW_ONLY", report, len(ordered), high_risk)
