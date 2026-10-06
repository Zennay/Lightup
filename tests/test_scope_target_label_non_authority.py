import ast
import inspect
import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeTargetLabelNonAuthorityTests(unittest.TestCase):
    def test_labels_cannot_authorize_unknown_public_host(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"allowed.example.test"}))

        decision = policy.decide(
            Target(
                "unknown.example.test",
                labels=("lab", "private_lab", "authorized", "allowed.example.test"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.normalized_host, "unknown.example.test")
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_labels_cannot_replace_explicit_host_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"security.example.test"}))

        decision = policy.decide(
            Target(
                "security.example.test",
                labels=("authorized", "AUTH-CURRENT", "lab"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_labels_cannot_replace_explicit_network_authorization(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24",))

        decision = policy.decide(
            Target(
                "8.8.8.8",
                labels=("authorized", "public-network", "8.8.8.0/24"),
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_labels_cannot_mint_or_remove_loopback_identity(self):
        disguised_public = ScopePolicy().decide(
            Target("unknown.example.test", labels=("localhost", "loopback"))
        )
        labelled_loopback = ScopePolicy().decide(
            Target("127.0.0.1", labels=("public", "untrusted"))
        )

        self.assertFalse(disguised_public.allowed)
        self.assertEqual(disguised_public.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertTrue(labelled_loopback.allowed)
        self.assertEqual(labelled_loopback.reason, ScopeReason.LOOPBACK)

    def test_scope_decision_does_not_read_target_labels(self):
        source = textwrap.dedent(inspect.getsource(ScopePolicy.decide))
        tree = ast.parse(source)
        label_reads = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "labels"
        ]

        self.assertEqual(
            label_reads,
            [],
            "ScopePolicy.decide must not use Target.labels as an authorization input",
        )


if __name__ == "__main__":
    unittest.main()
