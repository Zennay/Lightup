from __future__ import annotations

import unittest

from lightup.models import Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopePolicyMutableSnapshotAcceptanceTest(unittest.TestCase):
    def test_mutable_explicit_hosts_input_is_snapshotted(self):
        caller_hosts: set[str] = set()
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=caller_hosts,  # type: ignore[arg-type]
            require_authorization_for_public=False,
        )
        if not isinstance(policy.explicit_hosts, frozenset):
            self.fail("explicit_hosts mutable input was not snapshotted")

    def test_external_host_set_mutation_cannot_widen_existing_policy(self):
        caller_hosts: set[str] = set()
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=caller_hosts,  # type: ignore[arg-type]
            require_authorization_for_public=False,
        )
        target = Target("security.example.test")

        before = policy.decide(target)
        self.assertFalse(before.allowed)
        self.assertEqual(before.reason, ScopeReason.OUT_OF_SCOPE)

        caller_hosts.add("security.example.test")
        after = policy.decide(target)
        if after.allowed:
            self.fail("external host mutation widened existing scope policy")

    def test_mutable_explicit_networks_input_is_snapshotted(self):
        caller_networks: list[str] = []
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=caller_networks,  # type: ignore[arg-type]
            require_authorization_for_public=False,
        )
        if not isinstance(policy.explicit_networks, tuple):
            self.fail("explicit_networks mutable input was not snapshotted")

    def test_external_network_list_mutation_cannot_widen_existing_policy(self):
        caller_networks: list[str] = []
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=caller_networks,  # type: ignore[arg-type]
            require_authorization_for_public=False,
        )
        target = Target("8.8.8.8")

        before = policy.decide(target)
        self.assertFalse(before.allowed)
        self.assertEqual(before.reason, ScopeReason.OUT_OF_SCOPE)

        caller_networks.append("8.8.8.8/32")
        after = policy.decide(target)
        if after.allowed:
            self.fail("external network mutation widened existing scope policy")

    def test_canonical_immutable_policy_inputs_keep_existing_behavior(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=False,
        )
        self.assertTrue(policy.decide(Target("security.example.test")).allowed)
        self.assertTrue(policy.decide(Target("8.8.8.8")).allowed)


if __name__ == "__main__":
    unittest.main()
