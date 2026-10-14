#!/usr/bin/env python3
"""Offline fictional-only UTC window equality checker; never issues a permit.

This intentionally *never returns exit code zero*:
    2 = HOLD (invalid input or mismatching persisted strings)
    3 = REVIEW_ONLY (canonical strings equal, NOT consent/authorization)

It doesn't read files, real databases, network targets or real grants.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.grant_issuance_window_snapshot_647 import (
    WindowRejected, snapshot_grant_issuance_window,
)
from lightup.grant_window_storage_consistency_647 import (
    WindowStorageConsistencyReview,
    _canonical_utc_storage,
    review_grant_window_storage_consistency,
)

_FLAGS = frozenset((
    "--expected-start-utc", "--expected-until-utc",
    "--stored-start-utc", "--stored-until-utc",
))


def review_fixture_arguments(arguments: object) -> WindowStorageConsistencyReview:
    """Perform no I/O. Input is four short timestamp strings, no paths."""
    if type(arguments) not in (tuple, list) or len(arguments) != 8:
        return WindowStorageConsistencyReview("HOLD", "invalid_input")
    options = {}
    for key, value in zip(arguments[::2], arguments[1::2]):
        if type(key) is not str or key not in _FLAGS or key in options:
            return WindowStorageConsistencyReview("HOLD", "invalid_input")
        if type(value) is not str or len(value) > 40:
            return WindowStorageConsistencyReview("HOLD", "invalid_input")
        options[key] = value
    if set(options) != _FLAGS:
        return WindowStorageConsistencyReview("HOLD", "invalid_input")

    start = _canonical_utc_storage(options["--expected-start-utc"])
    if start is None:
        return WindowStorageConsistencyReview("HOLD", "expected_start")
    until = _canonical_utc_storage(options["--expected-until-utc"])
    if until is None:
        return WindowStorageConsistencyReview("HOLD", "expected_expiry")
    try:
        snapshot = snapshot_grant_issuance_window(start, until)
    except WindowRejected:
        return WindowStorageConsistencyReview("HOLD", "expected_window")
    return review_grant_window_storage_consistency(
        snapshot,
        stored_valid_from=options["--stored-start-utc"],
        stored_valid_until=options["--stored-until-utc"],
    )


def main(argv: object = None) -> int:
    try:
        result = review_fixture_arguments(sys.argv[1:] if argv is None else argv)
    except Exception:
        # Sanitized, fixed output: never print traceback/user-supplied values.
        result = WindowStorageConsistencyReview("HOLD", "invalid_input")
    sys.stdout.write(json.dumps(result.as_receipt(), sort_keys=True,
                                separators=(",", ":"), ensure_ascii=True) + "\n")
    return 3 if result.decision == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
