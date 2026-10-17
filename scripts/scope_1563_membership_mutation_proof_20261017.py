"""#1563: require negative scope regressions to catch deliberate fail-open mutations.

This is an *offline test-suite diagnostic*, never production code. Every broken
policy exists only under unittest.mock.patch and is restored automatically.
No DNS, network I/O, target interaction, grants, or dispatch occur.
"""
from __future__ import annotations

import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location(
    "test_scope_membership_metamorphic_20261017",
    ROOT / "tests" / "test_scope_membership_metamorphic_20261017.py",
)
if spec is None or spec.loader is None:
    raise SystemExit("HOLD: cannot load dedicated scope tests")
suite_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite_module)

from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason  # noqa: E402

REAL_DECIDE = ScopePolicy.decide


def run_suite() -> unittest.TestResult:
    suite = unittest.defaultTestLoader.loadTestsFromModule(suite_module)
    return unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)


def illegally_mint_membership(self, target):
    decision = REAL_DECIDE(self, target)
    if decision.reason == ScopeReason.OUT_OF_SCOPE:
        return ScopeDecision(True, decision.normalized_host, ScopeReason.EXPLICIT_HOST)
    return decision


def illegally_accept_invalid_target(self, target):
    decision = REAL_DECIDE(self, target)
    if decision.reason == ScopeReason.INVALID_TARGET:
        return ScopeDecision(True, decision.normalized_host, ScopeReason.LOOPBACK)
    return decision


def illegally_check_grant_before_membership(self, target):
    if target.authorization is not None:
        target.authorization.is_current()
    return REAL_DECIDE(self, target)


def illegally_honor_authorized_label(self, target):
    decision = REAL_DECIDE(self, target)
    if (
        "AUTHORIZED" in target.labels
        and decision.reason == ScopeReason.OUT_OF_SCOPE
    ):
        return ScopeDecision(True, decision.normalized_host, ScopeReason.EXPLICIT_HOST)
    return decision



def illegally_promote_cidr_right_neighbor(self, target):
    decision = REAL_DECIDE(self, target)
    if decision.reason == ScopeReason.OUT_OF_SCOPE and decision.normalized_host == "9.9.9.16":
        return ScopeDecision(True, decision.normalized_host, ScopeReason.EXPLICIT_NETWORK)
    return decision


def illegally_infer_wildcard_subdomain(self, target):
    decision = REAL_DECIDE(self, target)
    if (
        decision.reason == ScopeReason.OUT_OF_SCOPE
        and decision.normalized_host == "untrusted.scoped.example.test"
    ):
        return ScopeDecision(True, decision.normalized_host, ScopeReason.EXPLICIT_HOST)
    return decision


def illegally_rebind_denied_host_to_declared_host(self, target):
    decision = REAL_DECIDE(self, target)
    if (
        decision.reason == ScopeReason.OUT_OF_SCOPE
        and decision.normalized_host == "unlisted.example.test"
    ):
        return ScopeDecision(False, "declared.example.test", ScopeReason.OUT_OF_SCOPE)
    return decision


MUTATIONS = (
    ("grant_mints_membership", illegally_mint_membership, "test_undeclared_public_hostname"),
    ("invalid_identity_rescued", illegally_accept_invalid_target, "test_invalid_target"),
    ("grant_checked_before_scope", illegally_check_grant_before_membership, "test_undeclared_public_hostname"),
    ("spoofed_label_authorizes", illegally_honor_authorized_label, "test_untrusted_authorization_shape"),
    ("cidr_right_neighbor_authorizes", illegally_promote_cidr_right_neighbor, "test_ipv4_right_neighbor"),
    ("hostname_wildcard_authorizes", illegally_infer_wildcard_subdomain, "test_unlisted_subdomain"),
    ("denied_identity_rewritten", illegally_rebind_denied_host_to_declared_host, "test_normalized_host"),
)



def mutation_detected(result: unittest.TestResult, expected_test_prefix: str) -> bool:
    """Only real AssertionError safety denials count as killing a mutation.

    An import error, AttributeError, TimeoutError or other test crash is not
    evidence that a fail-open change was caught by the intended assertion.
    """
    if (
        result.testsRun != 13 or result.errors or result.expectedFailures
        or result.unexpectedSuccesses or not result.failures
    ):
        return False
    if not all("AssertionError:" in detail for _, detail in result.failures):
        return False
    return any(
        expected_test_prefix in str(case) for case, _ in result.failures
    )



def main() -> int:
    baseline = run_suite()
    if not baseline.wasSuccessful() or baseline.testsRun != 13:
        print(
            "HOLD: all 13 negative regressions must pass first; "
            f"ran={baseline.testsRun} failures={len(baseline.failures)} "
            f"errors={len(baseline.errors)}"
        )
        return 2

    for name, broken, expected_test_prefix in MUTATIONS:
        with patch.object(ScopePolicy, "decide", broken):
            result = run_suite()
        if not mutation_detected(result, expected_test_prefix):
            print(
                f"HOLD: mutation {name} was NOT detected by the expected contract "
                f"(ran={result.testsRun}, assertions={len(result.failures)}, "
                f"unexpected_errors={len(result.errors)})"
            )
            return 2
        print(f"DETECTED {name}: {len(result.failures)} assertion-based negative regressions failed")

    if ScopePolicy.decide is not REAL_DECIDE:
        print("HOLD: ScopePolicy restored function identity changed")
        return 2
    print("PASS: clean baseline and all seven fail-open mutation canaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
