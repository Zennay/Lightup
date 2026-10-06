import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class TargetLabelNonAuthorityTests(unittest.TestCase):
    def test_authority_like_labels_do_not_allow_unknown_public_host(self):
        decision = ScopePolicy().decide(
            Target(
                "unlisted.example.test",
                labels=("lab", "private_lab", "authorized", "localhost", "security.example.test"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "unlisted.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_labels_do_not_replace_authorization_for_explicit_public_host(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        decision = policy.decide(
            Target(
                "security.example.test",
                labels=("authorized", "client-approved", "security.example.test"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_labels_do_not_replace_authorization_for_explicit_public_network(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))

        decision = policy.decide(
            Target(
                "8.8.8.8",
                labels=("authorized", "network-approved", "8.8.8.0/24"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_loopback_classification_depends_on_target_identity_not_labels(self):
        labeled_public = ScopePolicy().decide(
            Target("public.example.test", labels=("localhost", "loopback", "127.0.0.1"))
        )
        unlabeled_loopback = ScopePolicy().decide(Target("127.0.0.1", labels=("public",)))

        self.assertFalse(labeled_public.allowed)
        self.assertEqual(labeled_public.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertTrue(unlabeled_loopback.allowed)
        self.assertEqual(unlabeled_loopback.reason, ScopeReason.LOOPBACK)


if __name__ == "__main__":
    unittest.main()
