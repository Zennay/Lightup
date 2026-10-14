#!/usr/bin/env python3
"""Read-only synthetic UTC grant-window SHAPE review (#738).

Never exits zero: 3=REVIEW_ONLY, 2=HOLD. No customer data/target I/O/consent.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.direct_grant_window_shape_review_738 import (
    WindowShapeReview, review_direct_grant_window_shape
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


_KEY_NAMES = frozenset(("--from-utc", "--until-utc", "--observed-at-utc"))
_CANONICAL_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)


def _parse_utc(value: object) -> datetime:
    if type(value) is not str or len(value) != 20 or not value.isascii():
        raise ValueError("not canonical UTC")
    if _CANONICAL_UTC.fullmatch(value) is None:
        raise ValueError("not canonical UTC")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return parsed.replace(tzinfo=timezone.utc)


def _evaluate(argv: object) -> WindowShapeReview:
    # Refuse unknown flags, duplicates, missing fields and extra positional args.
    # Never include input in any output; no file paths or identifiers accepted.
    if type(argv) not in (list, tuple) or len(argv) != 6:
        return WindowShapeReview("HOLD", "invalid_input")
    if any(type(item) is not str or len(item) > 32 for item in argv):
        return WindowShapeReview("HOLD", "invalid_input")
    options = {}
    for key, value in zip(argv[::2], argv[1::2]):
        if key not in _KEY_NAMES or key in options:
            return WindowShapeReview("HOLD", "invalid_input")
        options[key] = value
    if set(options) != _KEY_NAMES:
        return WindowShapeReview("HOLD", "invalid_input")
    try:
        starts = _parse_utc(options["--from-utc"])
        ends = _parse_utc(options["--until-utc"])
        observed = _parse_utc(options["--observed-at-utc"])
    except (ValueError, TypeError, OverflowError):
        return WindowShapeReview("HOLD", "invalid_input")

    # Always construct an obviously fictional locally supplied grant. There
    # is no real caller-supplied client, signature, permit, capability or asset.
    synthetic = AuthorizationGrant(
        grant_id="offline-fiction",
        client_id="offline-fiction",
        engagement_id="offline-fiction",
        approved_by="nobody@example.test",
        reference="NOT_CONSENT",
        scope=ScopeDefinition(
            assets=("fixture.example.test",),
            max_risk=RiskLevel.ANALYSIS_ONLY,
            allowed_capabilities=("web-baseline",),
        ),
        valid_from=starts,
        valid_until=ends,
    )
    return review_direct_grant_window_shape(synthetic, observed_at=observed)


def main(argv: object = None) -> int:
    try:
        receipt = _evaluate(sys.argv[1:] if argv is None else argv)
    except Exception:
        # Defense in depth: no exception detail/argument values in output.
        receipt = WindowShapeReview("HOLD", "invalid_input")
    sys.stdout.write(json.dumps(
        receipt.as_receipt(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ) + "\n")
    return 3 if receipt.decision == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
