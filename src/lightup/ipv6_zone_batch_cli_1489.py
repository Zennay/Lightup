"""Bounded, non-authorizing fictional IPv6 zone review batch + stdin CLI (#1489).

This opt-in preview is NOT wired to ScopePolicy, ActivationGate, dispatch,
customer grant persistence, network adapters, or release. Both possible CLI
exit codes are nonzero and every response contains four literal false flags.
"""
from __future__ import annotations

import json
import sys
from urllib.parse import urlsplit

from .ipv6_zone_review_1489 import (
    ZoneReview,
    ZoneReviewStatus,
    review_ipv6_authority_zone,
)

SCHEMA = "LIGHTUP-FICTIONAL-IPV6-ZONE-REVIEW-V1"
MAX_INPUT_BYTES = 16_384
MAX_AUTHORITIES = 64

_HOLD = ZoneReview(ZoneReviewStatus.HOLD, "invalid-or-ambiguous-synthetic-batch")
_REVIEW = ZoneReview(ZoneReviewStatus.REVIEW_ONLY, "fictional-batch-shape-only")


def review_ipv6_zone_batch(authorities: object) -> ZoneReview:
    """Atomically check only shape; never grant any form of authority."""
    if type(authorities) is not list or not 1 <= len(authorities) <= MAX_AUTHORITIES:
        return _HOLD
    identities: set[str] = set()
    for value in authorities:
        verdict = review_ipv6_authority_zone(value)
        if verdict.status is not ZoneReviewStatus.REVIEW_ONLY:
            return _HOLD
        # Only parse after strict single-identity validation. Treat URL/literal
        # wrappers around the same exact IPv6 host as duplicate identity claims.
        authority = urlsplit(value).netloc if "://" in value else value
        host = authority[1:-1]
        if host in identities:
            return _HOLD
        identities.add(host)
    return _REVIEW


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON token")


def review_stdin_document(raw: object) -> ZoneReview:
    """Evaluate exact synthetic schema only; fail closed on JSON ambiguity."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT_BYTES:
        return _HOLD
    try:
        decoded = raw.decode("utf-8", "strict")
        data = json.loads(
            decoded,
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError):
        return _HOLD
    if type(data) is not dict or set(data) != {"schema", "authorities"}:
        return _HOLD
    if type(data["schema"]) is not str or data["schema"] != SCHEMA:
        return _HOLD
    return review_ipv6_zone_batch(data["authorities"])


def _public_response(verdict: ZoneReview) -> str:
    """No raw input, operator IDs, assets, URL, IPs, or contents in output."""
    return json.dumps(
        {
            "status": verdict.status.value,
            "execution_allowed": False,
            "permit_allowed": False,
            "dispatch_allowed": False,
            "release_allowed": False,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args != ["--synthetic-only"]:
        print(_public_response(_HOLD))
        return 2
    try:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        verdict = review_stdin_document(data)
    except (OSError, ValueError, RecursionError):
        verdict = _HOLD
    print(_public_response(verdict))
    # Returning success MUST NEVER be mistaken for a permit or a release gate.
    return 3 if verdict.status is ZoneReviewStatus.REVIEW_ONLY else 2


if __name__ == "__main__":
    raise SystemExit(main())
