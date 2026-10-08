"""Offline RED contract: Unicode host identity must not silently inherit ASCII scope.

This is intentionally a failing acceptance suite until the ScopePolicy owner
implements explicit IDNA handling or strict rejection. No sockets or scans.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class UnicodeHostIdentityContract(unittest.TestCase):
    def test_unicode_hostname_cannot_gain_ascii_host_authority(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"xn--bcher-kva.example.test"}),
                             require_authorization_for_public=False)
        decision = policy.decide(Target("https://bücher.example.test"))
        # Either reject the non-ASCII authority or canonicalize deliberately to
        # the configured A-label. Never treat these as two arbitrary aliases.
        self.assertTrue(
            decision.reason == ScopeReason.INVALID_TARGET
            or (decision.allowed and decision.normalized_host == "xn--bcher-kva.example.test"),
            f"host identity silently mismatched: {decision.reason}",
        )

    def test_ascii_alabel_still_requires_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"xn--bcher-kva.example.test"}))
        decision = policy.decide(Target("https://xn--bcher-kva.example.test"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_idna_label_does_not_authorize_subdomain(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"xn--bcher-kva.example.test"}),
                             require_authorization_for_public=False)
        decision = policy.decide(Target("https://child.xn--bcher-kva.example.test"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_ascii_allowlist_remains_usable(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"xn--bcher-kva.example.test"}),
                             require_authorization_for_public=False)
        decision = policy.decide(Target("https://xn--bcher-kva.example.test"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXPLICIT_HOST)

    def test_unlisted_unicode_confusable_never_inherits_ascii_grant(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"paypal.example.test"}),
                             require_authorization_for_public=False)
        decision = policy.decide(Target("https://pаypal.example.test"))
        # Second letter of the target is Cyrillic, not ASCII.
        self.assertFalse(decision.allowed)

    def test_unicode_explicit_host_must_not_become_unreachable_alias(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"bücher.example.test"}),
                             require_authorization_for_public=False)
        decision = policy.decide(Target("https://xn--bcher-kva.example.test"))
        self.assertTrue(
            decision.reason == ScopeReason.INVALID_TARGET
            or (decision.allowed and decision.normalized_host == "xn--bcher-kva.example.test"),
            f"noncanonical host allowlist: {decision.reason}",
        )


if __name__ == "__main__":
    unittest.main()
