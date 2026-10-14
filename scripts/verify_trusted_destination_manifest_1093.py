"""Exact local checkout, offline scope #1093 test gate; never a release permit.

Run using the existing checked-out, owner-authorized GitHub Actions job:
    python scripts/verify_trusted_destination_manifest_1093.py

This does not run a scanner, resolve a target, mint a grant, or attest that a
GitHub runner is trusted. CI must independently pin the workflow's head SHA.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest


EXPECTED_TEST_METHODS = 91
PATTERN = "test_trusted_destination_manifest_optin_1093.py"


def _receipt(passed: bool, count: int) -> dict[str, object]:
    return {
        "schema": "lightup-scope-1093-offline-v1",
        "status": "hold",
        "offline_regression_passed": passed,
        "tests_run": count,
        "expected_tests": EXPECTED_TEST_METHODS,
        "authorization_verified": False,
        "permit_issued": False,
        "execution_enabled": False,
        "release_approved": False,
    }


def main() -> int:
    # This is a fixed test-gate entrypoint; do not accept paths, target names
    # or workflow identifiers from a caller.
    if len(sys.argv) != 1:
        print(json.dumps(_receipt(False, 0), sort_keys=True))
        return 2

    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "src"))
    sys.path.insert(0, str(root / "tests"))
    if not (root / "tests" / PATTERN).is_file():
        print(json.dumps(_receipt(False, 0), sort_keys=True))
        return 2

    # No external test selection or follow-up dispatch is possible. Standard
    # unittest reports are kept out of the machine-readable minimal receipt.
    try:
        suite = unittest.TestLoader().discover(
            start_dir=str(root / "tests"),
            pattern=PATTERN,
            top_level_dir=str(root / "tests"),
        )
        log = io.StringIO()
        result = unittest.TextTestRunner(
            stream=log, verbosity=0, failfast=True
        ).run(suite)
        passed = (
            result.wasSuccessful()
            and result.testsRun == EXPECTED_TEST_METHODS
            and not result.skipped
            and not result.expectedFailures
            and not result.unexpectedSuccesses
        )
        count = result.testsRun
    except Exception:
        passed, count = False, 0

    print(json.dumps(_receipt(passed, count), sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
