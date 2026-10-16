#!/usr/bin/env python3
"""Strict *non-authorizing* opt-in harness for #1480 original-source RED.

Run only in an isolated review branch. Exit 0 attests 31 ordinary controls +
1 original-source expected RED, never a fixed source or release.
No network, subprocess, active adapters, real grant issuance, or target IO.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN_TEST_FILES = (
    "test_scope_1480_activation_issuance_instant_20261016.py",
    "test_scope_1480_issuance_window_review_20261016.py",
    "test_scope_1480_issuance_transition_20261016.py",
    "test_scope_1480_local_source_reference_20261016.py",
)
ACTIVATION = ROOT / "src" / "lightup" / "activation.py"
ORIGINAL_SOURCE_BLOB = "156e94c18d5221b3d55e2c9fff4e393369e0f38e"
EXPECTED_RED = "test_expected_red_authorized_permit_cannot_be_stamped_after_expiry"
EXPECTED_METHODS = 32


def _original_source_is_pinned() -> bool:
    try:
        if ACTIVATION.is_symlink() or not ACTIVATION.is_file():
            return False
        if ACTIVATION.stat().st_size > 100_000:
            return False
        contents = ACTIVATION.read_bytes()
        framed = b"blob " + str(len(contents)).encode("ascii") + b"\0" + contents
        return hashlib.sha1(framed).hexdigest() == ORIGINAL_SOURCE_BLOB
    except (OSError, ValueError):
        return False


def _verdict(status: str, reason: str, tests: int = 0, expected_source_reds: int = 0) -> dict:
    return {
        "issue": 1480,
        "status": status,
        "reason": reason,
        "tests_run": tests,
        "expected_source_reds": expected_source_reds,
        "source_fixed": False,
        "full_suite_green": False,
        "permanent_vps_proven": False,
        "consent_verified": False,
        "revocation_verified": False,
        "may_issue_grants": False,
        "may_dispatch_tools": False,
        "may_scan_targets": False,
        "may_merge": False,
        "may_deploy": False,
        "release_authorized": False,
    }


def main() -> int:
    # The only accepted source is the exact installed main source inspected
    # when filing #1480. Do not silently promote a repaired or drifted source.
    if not _original_source_is_pinned():
        print(json.dumps(_verdict("HOLD", "original_activation_source_blob_mismatch"), sort_keys=True))
        return 1
    for filename in OWN_TEST_FILES:
        test_path = ROOT / "tests" / filename
        if test_path.is_symlink() or not test_path.is_file():
            print(json.dumps(_verdict("HOLD", "test_module_missing_or_symlinked"), sort_keys=True))
            return 1

    sys.path.insert(0, str(ROOT / "src"))
    suite = unittest.TestSuite()
    for filename in OWN_TEST_FILES:
        suite.addTests(unittest.defaultTestLoader.discover(
            start_dir=str(ROOT / "tests"), pattern=filename,
        ))
    capture = io.StringIO()
    result = unittest.TextTestRunner(stream=capture, verbosity=2).run(suite)
    red_is_exact = (
        len(result.expectedFailures) == 1
        and EXPECTED_RED in result.expectedFailures[0][0].id()
        and "AssertionError: PermissionError not raised" in result.expectedFailures[0][1]
    )
    okay = (
        result.testsRun == EXPECTED_METHODS
        and red_is_exact
        and not result.failures
        and not result.errors
        and not result.skipped
        and not result.unexpectedSuccesses
    )
    print(
        json.dumps(
            _verdict(
                "REVIEW_ONLY" if okay else "HOLD",
                "original_source_gap_reproduced" if okay else "test_contract_mismatch",
                result.testsRun,
                len(result.expectedFailures),
            ),
            sort_keys=True,
        )
    )
    if not okay:
        print(capture.getvalue(), file=sys.stderr)
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
