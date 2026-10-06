import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyMonotonicityTest(unittest.TestCase):
    def assertNarrower(self, broader, narrower, target, denied_reason):
        broader_decision = broader.decide(target)
        narrower_decision = narrower.decide(target)

        self.assertTrue(broader_decision.allowed)
        self.assertFalse(narrower_decision.allowed)
        self.assertEqual(narrower_decision.reason, denied_reason)
        self.assertEqual(
            broader_decision.normalized_host,
            narrower_decision.normalized_host,
        )

    def test_removing_explicit_host_only_reduces_authority(self):
        target = Target("https://Security.Example.Test./app")
        broader = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=False,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(),
            require_authorization_for_public=False,
        )

        self.assertNarrower(
            broader,
            narrower,
            target,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_requiring_public_authorization_only_reduces_host_authority(self):
        target = Target("security.example.test")
        broader = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=False,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            require_authorization_for_public=True,
        )

        self.assertNarrower(
            broader,
            narrower,
            target,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_removing_explicit_network_only_reduces_authority(self):
        target = Target("8.8.8.8")
        broader = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(),
            require_authorization_for_public=False,
        )

        self.assertNarrower(
            broader,
            narrower,
            target,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_requiring_public_authorization_only_reduces_network_authority(self):
        target = Target("8.8.8.8")
        broader = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )

        self.assertNarrower(
            broader,
            narrower,
            target,
            ScopeReason.AUTHORIZATION_MISSING,
        )

    def test_disabling_private_lab_only_reduces_private_address_authority(self):
        target = Target("10.23.45.67")
        broader = ScopePolicy(
            allow_private_lab=True,
            explicit_networks=(),
            require_authorization_for_public=True,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=(),
            require_authorization_for_public=True,
        )

        self.assertNarrower(
            broader,
            narrower,
            target,
            ScopeReason.OUT_OF_SCOPE,
        )

    def test_narrowing_unrelated_entries_does_not_widen_denied_target(self):
        target = Target("unknown.example.test")
        broader = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"a.example.test", "b.example.test"}),
            explicit_networks=("8.8.8.0/24", "1.1.1.0/24"),
            require_authorization_for_public=False,
        )
        narrower = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"a.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )

        broader_decision = broader.decide(target)
        narrower_decision = narrower.decide(target)

        self.assertFalse(broader_decision.allowed)
        self.assertFalse(narrower_decision.allowed)
        self.assertEqual(broader_decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(narrower_decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(
            broader_decision.normalized_host,
            narrower_decision.normalized_host,
        )


if __name__ == "__main__":
    unittest.main()
