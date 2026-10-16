#!/usr/bin/env python3
"""Opt-in, offline #920 current-main acceptance; NEVER release authority.

This intentionally runs *only* the independently owned #920 test file, not
the entire suite: the unrelated frozen-date #301 test is already known to
make current-main full-suite CI fail after 2026-10-15. It does not hide or
mark that full-suite failure green.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATTERN = "test_scope_920_current_main_proxy_origin_wsgi_20261016.py"
EXPECTED_METHODS = 20
EXPECTED_SOURCE_REDS = 9
# Git blob ID of the precise current-main WebSecurity source under acceptance.
# This is a local drift guard, NOT a signature, attestation, or release proof.
PINNED_SOURCE_BLOB = "ca657372e43a15f212b3b7c92605f9f29e055531"
MAX_SOURCE_BYTES = 65536


def git_blob_id(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + bytes((0,))
    return hashlib.sha1(header + content).hexdigest()


def source_is_pinned() -> bool:
    path = ROOT / "src" / "lightup" / "webapp" / "security.py"
    try:
        if path.is_symlink() or not path.is_file():
            return False
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return False
        return git_blob_id(path.read_bytes()) == PINNED_SOURCE_BLOB
    except OSError:
        return False



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
    # Before running tests, reject any source drift from the pinned main blob.
    # This never reads customer files and makes no network/subprocess calls.
    if not source_is_pinned():
        print(receipt(status="HOLD", methods=0, source_reds=0))
        return 2
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
