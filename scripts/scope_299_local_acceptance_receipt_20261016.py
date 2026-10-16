"""Opt-in, hermetic, non-authorizing #299 current-source acceptance summary.

Only tests owned by draft #1468, in process and against installed local source.
Never accepts or reads customer records/targets; no subprocess shells or files.
A result matching intentional REDs is an OPEN-SAFETY-DEBT receipt, never PASS
for production, customer authorization, CI, deployment or release.
"""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TEST_MODULES = (
    "test_scope_299_legacy_provenance_red_20261015",
    "test_scope_299_legacy_provenance_review_20261016",
    "test_scope_299_legacy_pair_review_20261016",
)
EXPECTED_TESTS = 63
EXPECTED_SOURCE_REDS = 16
FALSE_AUTHORITIES = {
    "can_authorize": False,
    "can_dispatch": False,
    "can_deploy": False,
    "can_merge": False,
    "can_release": False,
    "can_scan": False,
}


def receipt(reason: str) -> str:
    if reason not in {"open_source_reds_observed", "contract_changed", "invalid_command"}:
        reason = "contract_changed"
    return json.dumps(
        {"status": "HOLD", "reason": reason, "evidence_class": "local_untrusted",
         **FALSE_AUTHORITIES},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )


def _forbid_network(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("network and DNS forbidden in #299 local acceptance")


def run_local_tests() -> bool:
    # A test suite may import the repo's current installed source only; no target
    # arguments, remote repositories or production config are accepted.
    original_sys_path = sys.path[:]
    sys.path.insert(0, str(ROOT / "tests"))
    sys.path.insert(0, str(ROOT / "src"))
    try:
        with (
            mock.patch.object(socket, "socket", side_effect=_forbid_network),
            mock.patch.object(socket, "create_connection", side_effect=_forbid_network),
            mock.patch.object(socket, "getaddrinfo", side_effect=_forbid_network),
            mock.patch.object(socket, "gethostbyname", side_effect=_forbid_network),
            mock.patch.object(socket, "gethostbyname_ex", side_effect=_forbid_network),
        ):
            suite = unittest.defaultTestLoader.loadTestsFromNames(TEST_MODULES)
            result = unittest.TestResult()
            suite.run(result)
            return (
                result.testsRun == EXPECTED_TESTS
                and len(result.expectedFailures) == EXPECTED_SOURCE_REDS
                and not result.errors
                and not result.failures
                and not result.skipped
                and not result.unexpectedSuccesses
                # Exactly 16 expected failures, all owned by installed-source
                # tests; synthetic-only subprocess suites are always green.
                and all(
                    case.__class__.__name__ == "LegacyAuthorization299Tests"
                    for case, _detail in result.expectedFailures
                )
            )
    except (Exception, KeyboardInterrupt):
        # The output never echoes exception text, source input or paths.
        return False
    finally:
        # Installed-source test imports also add a src path; restore the full
        # original list, not just the two entries inserted by this function.
        sys.path[:] = original_sys_path


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--offline-local-suite-only"]:
        print(receipt("invalid_command"))
        return 3
    matching = run_local_tests()
    print(receipt("open_source_reds_observed" if matching else "contract_changed"))
    return 2 if matching else 3


if __name__ == "__main__":
    raise SystemExit(main())
