"""Offline regression: X-Original-Host is never a target authorization source.

These tests exercise the existing pure ScopePolicy API. They do not authorize
network requests or represent trusted, persisted customer consent.
"""
import unittest

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class OriginalHostNonAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example"}),
        )

    def test_unknown_host_denied_despite_original_host_label(self):
        for hint in (
            "X-Original-Host: approved.example",
            "x-original-host=approved.example",
            "X-Original-Host: APPROVED.EXAMPLE",
            "X-Original-Host: approved.example:443",
            "X-Original-Host: approved.example, unknown.example",
        ):
            with self.subTest(hint=hint):
                target = Target("unknown.example", labels=(hint,))
                result = self.policy.decide(target)
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)
                self.assertEqual(result.normalized_host, "unknown.example")

    def test_hint_does_not_replace_missing_grant_for_allowlisted_host(self):
        result = self.policy.decide(
            Target("approved.example", labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_hint_does_not_authorize_unlisted_host_even_with_synthetic_grant(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        result = self.policy.decide(
            Target("unknown.example", authorization=synthetic,
                   labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)

    def test_hint_does_not_deny_authorized_host_by_rewriting_identity(self):
        synthetic = Authorization(owner="fixture", reference="NOT-TRUSTED")
        result = self.policy.decide(
            Target("approved.example", authorization=synthetic,
                   labels=("X-Original-Host: unknown.example",))
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(result.normalized_host, "approved.example")

    def test_forwarding_label_does_not_override_url_authority(self):
        result = self.policy.decide(
            Target("https://unknown.example/path",
                   labels=("X-Original-Host: approved.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, "unknown.example")

    def test_userinfo_in_hint_never_replaces_target_authority(self):
        result = self.policy.decide(
            Target("https://unknown.example/",
                   labels=("X-Original-Host: approved.example@unknown.example",))
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
