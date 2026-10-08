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
