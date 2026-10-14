"""Exact local checkout, offline scope #1093 test gate; never a release permit.

Run using the existing checked-out, owner-authorized GitHub Actions job:
    python scripts/verify_trusted_destination_manifest_1093.py

This does not run a scanner, resolve a target, mint a grant, or attest that a
GitHub runner is trusted. CI must independently pin the workflow's head SHA.
"""
from __future__ import annotations

import io
from contextlib import redirect_stdout, redirect_stderr
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


EXPECTED_TEST_METHODS = 91
PATTERN = "test_trusted_destination_manifest_optin_1093.py"


def _receipt(
    passed: bool, count: int, failures: int = 0,
    errors: int = 0, skipped: int = 0
) -> dict[str, object]:
    return {
        "schema": "lightup-scope-1093-offline-v1",
        "status": "hold",
        "offline_regression_passed": passed,
        "tests_run": count,
        "expected_tests": EXPECTED_TEST_METHODS,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
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
        log = io.StringIO()
        def refuse_io(*_args, **_kwargs):
            raise RuntimeError("offline test boundary refused external I/O")

        # Defense in depth: even an accidental future test regression must
        # not be able to open network sockets or spawn external processes.
        with (patch("socket.socket", side_effect=refuse_io),
              patch("socket.create_connection", side_effect=refuse_io),
              patch("socket.getaddrinfo", side_effect=refuse_io),
              patch("urllib.request.urlopen", side_effect=refuse_io),
              patch("subprocess.Popen", side_effect=refuse_io),
              patch("subprocess.run", side_effect=refuse_io),
              patch("os.system", side_effect=refuse_io),
              redirect_stdout(log),
              redirect_stderr(log)):
            # Discovery imports test modules and their dependencies. Protect
            # BOTH discovery and execution against eager import-time I/O.
            suite = unittest.TestLoader().discover(
                start_dir=str(root / "tests"),
                pattern=PATTERN,
                top_level_dir=str(root / "tests"),
            )
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
        failures, errors, skipped = (
            len(result.failures), len(result.errors), len(result.skipped)
        )
    except Exception:
        passed, count = False, 0
        failures, errors, skipped = 0, 1, 0

    print(json.dumps(
        _receipt(passed, count, failures, errors, skipped), sort_keys=True
    ))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
