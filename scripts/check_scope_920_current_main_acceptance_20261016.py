#!/usr/bin/env python3
"""Opt-in, offline #920 current-main acceptance; NEVER release authority.

This intentionally runs *only* the independently owned #920 test file, not
the entire suite: the unrelated frozen-date #301 test is already known to
make current-main full-suite CI fail after 2026-10-15. It does not hide or
mark that full-suite failure green.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATTERN = "test_scope_920_current_main_proxy_origin_wsgi_20261016.py"
EXPECTED_METHODS = 20
EXPECTED_SOURCE_REDS = 9


def receipt(*, status: str, methods: int, source_reds: int) -> str:
    return json.dumps(
        {
            "status": status,
            "tests_run": methods,
            "expected_source_failures": source_reds,
            "source_fixed": False,
            "release_authorized": False,
            "merge_authorized": False,
            "scan_authorized": False,
            "dispatch_authorized": False,
            "registered_vps_verified": False,
            "full_suite_verified": False,
            "client_operator_consent_verified": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def main() -> int:
    # No external tool calls, network clients, subprocess, customer files or DB.
    sys.path.insert(0, str(ROOT / "src"))
    tests_dir = ROOT / "tests"
    suite = unittest.TestLoader().discover(
        start_dir=str(tests_dir),
        pattern=PATTERN,
        top_level_dir=str(tests_dir),
    )
    if suite.countTestCases() != EXPECTED_METHODS:
        print(receipt(status="HOLD", methods=suite.countTestCases(),
                      source_reds=0))
        return 2

    outcome = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    passed = (
        outcome.wasSuccessful()
        and outcome.testsRun == EXPECTED_METHODS
        and len(outcome.expectedFailures) == EXPECTED_SOURCE_REDS
        and not outcome.skipped
        and not outcome.unexpectedSuccesses
    )
    print(receipt(
        status="REVIEW_ONLY" if passed else "HOLD",
        methods=outcome.testsRun,
        source_reds=len(outcome.expectedFailures),
    ))
    # Exit 0 signals only test execution success, NEVER permission to deploy.
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
