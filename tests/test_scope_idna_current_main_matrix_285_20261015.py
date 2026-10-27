"""Current-main, in-memory alias-isolation acceptance for #285.

These tests do not create customer grants, invoke ToolExecutor, or contact targets.
A synthetic Authorization is a fixture for ScopePolicy behavior ONLY.
The source owner, not this acceptance pack, owns any production changes.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


# Non-secret fictitious object: not evidence of customer consent or grant issuance.
FAKE_AUTH = Authorization(owner="offline-fixture-only", reference="NOT-A-REAL-GRANT")


def _policy(*hosts: str) -> ScopePolicy:
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset(hosts),
        explicit_networks=(),
        require_authorization_for_public=True,
    )


def _decide(allowed_host: str, candidate: str, *, with_fixture=True) -> ScopeDecision:
    return _policy(allowed_host).decide(
        Target(candidate, authorization=FAKE_AUTH if with_fixture else None)
    )


class CurrentMainHostAliasAuthorityTests(unittest.TestCase):
    def test_host_allowlist_does_not_cross_unicode_punycode_equivalence(self):
        for approved, alternate in (
            ("bücher.example", "xn--bcher-kva.example"),
            ("xn--bcher-kva.example", "bücher.example"),
            ("café.example", "xn--caf-dma.example"),
            ("xn--caf-dma.example", "café.example"),
        ):
            for candidate in (alternate, f"https://{alternate}/status"):
                with self.subTest(approved=approved, candidate=candidate):
                    decision = _decide(approved, candidate)
                    self.assertIs(type(decision), ScopeDecision)
                    self.assertIs(decision.allowed, False)
                    self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_composed_and_decomposed_unicode_hosts_require_distinct_scope(self):
        composed = "café.example"
        decomposed = "cafe\u0301.example"
        for approved, alternate in ((composed, decomposed), (decomposed, composed)):
            for candidate in (alternate, f"https://{alternate}/status"):
                with self.subTest(approved=approved, candidate=candidate):
                    decision = _decide(approved, candidate)
                    self.assertIs(decision.allowed, False)
                    self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_unicode_dot_lookalikes_never_inherit_ascii_host_scope(self):
        approved = "security.example.test"
        for dot in ("\u3002", "\uff0e", "\uff61"):
            candidate = f"security{dot}example{dot}test"
            for spelling in (candidate, f"https://{candidate}/check"):
                with self.subTest(spelling=spelling):
                    decision = _decide(approved, spelling)
                    self.assertIs(decision.allowed, False)
                    self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_identity_normalizes_case_and_trailing_dot_only(self):
        for approved, candidate in (
            ("bücher.example", "BÜCHER.EXAMPLE."),
            ("xn--bcher-kva.example", "XN--BCHER-KVA.EXAMPLE."),
            ("café.example", "CAFÉ.EXAMPLE."),
            ("security.example.test", "SECURITY.EXAMPLE.TEST."),
        ):
            with self.subTest(approved=approved):
                decision = _decide(approved, f"https://{candidate}/status")
                self.assertIs(decision.allowed, True)
                self.assertIs(decision.reason, ScopeReason.EXPLICIT_HOST)
                self.assertEqual(decision.normalized_host, approved)

    def test_exact_host_requires_separate_authorization_even_for_fixture(self):
        for approved in ("bücher.example", "xn--bcher-kva.example", "security.example.test"):
            with self.subTest(approved=approved):
                decision = _decide(approved, approved, with_fixture=False)
                self.assertIs(decision.allowed, False)
                self.assertIs(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_undeclared_unicode_hosts_fail_closed_with_empty_allowlist(self):
        policy = _policy()
        for candidate in ("δοκιμή.example", "bücher.example", "cafe\u0301.example"):
            with self.subTest(candidate=candidate):
                decision = policy.decide(Target(candidate, authorization=FAKE_AUTH))
                self.assertIs(decision.allowed, False)
                self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_denial_does_not_modify_inputs(self):
        policy = _policy("xn--bcher-kva.example")
        target = Target("https://bücher.example/path", authorization=FAKE_AUTH)
        before = (policy, target, target.value, target.authorization)
        first = policy.decide(target)
        second = policy.decide(target)
        self.assertEqual(first, second)
        self.assertIs(first.allowed, False)
        self.assertIs(policy, before[0])
        self.assertIs(target, before[1])
        self.assertEqual(target.value, before[2])
        self.assertIs(target.authorization, before[3])

    def test_policy_path_requires_no_socket_dns_or_subprocess(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            rejected = _decide("xn--bcher-kva.example", "bücher.example")
            matching = _decide("xn--bcher-kva.example", "xn--bcher-kva.example")
        self.assertIs(rejected.allowed, False)
        self.assertIs(matching.allowed, True)


if __name__ == "__main__":
    unittest.main()
