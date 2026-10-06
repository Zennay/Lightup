import unittest
from datetime import datetime, timezone

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class ScopeDecisionPurityTest(unittest.TestCase):
    def test_explicit_host_decision_is_repeatable_and_input_pure(self):
        authorization = Authorization(
            owner="Client Security",
            reference="AUTH-344-HOST",
            valid_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2027, 1, 1, tzinfo=timezone.utc),
        )
        target = Target(
            "https://SECURITY.EXAMPLE.TEST./app?probe=none#fragment",
            authorization=authorization,
            labels=("descriptive", "authorized"),
        )
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        )
        target_before = (
            target.value,
            target.labels,
            target.authorization.owner,
            target.authorization.reference,
            target.authorization.valid_from,
            target.authorization.valid_until,
        )
        policy_before = (
            policy.allow_private_lab,
            policy.explicit_hosts,
            policy.explicit_networks,
            policy.require_authorization_for_public,
        )

        first = policy.decide(target)
        second = policy.decide(target)

        self.assertEqual(first, second)
        self.assertTrue(first.allowed)
        self.assertEqual(first.normalized_host, "security.example.test")
        self.assertEqual(first.reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(
            (
                target.value,
                target.labels,
                target.authorization.owner,
                target.authorization.reference,
                target.authorization.valid_from,
                target.authorization.valid_until,
            ),
            target_before,
        )
        self.assertEqual(
            (
                policy.allow_private_lab,
                policy.explicit_hosts,
                policy.explicit_networks,
                policy.require_authorization_for_public,
            ),
            policy_before,
        )

    def test_explicit_network_decision_is_repeatable_and_does_not_rewrite_policy(self):
        target = Target("8.8.8.8", labels=("inventory",))
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.0/24", "1.1.1.1/32"),
            require_authorization_for_public=False,
        )
        explicit_hosts_before = policy.explicit_hosts
        explicit_networks_before = policy.explicit_networks

        decisions = tuple(policy.decide(target) for _ in range(3))

        self.assertEqual(decisions, (decisions[0],) * 3)
        self.assertTrue(decisions[0].allowed)
        self.assertEqual(decisions[0].normalized_host, "8.8.8.8")
        self.assertEqual(decisions[0].reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertIs(policy.explicit_hosts, explicit_hosts_before)
        self.assertIs(policy.explicit_networks, explicit_networks_before)
        self.assertEqual(target, Target("8.8.8.8", labels=("inventory",)))

    def test_out_of_scope_decision_stays_denied_across_repeated_evaluation(self):
        target = Target("unknown.example.test", labels=("lab", "authorized"))
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"security.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )

        first = policy.decide(target)
        second = policy.decide(target)

        self.assertEqual(first, second)
        self.assertFalse(first.allowed)
        self.assertEqual(first.normalized_host, "unknown.example.test")
        self.assertEqual(first.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(target.value, "unknown.example.test")
        self.assertEqual(target.labels, ("lab", "authorized"))

    def test_loopback_normalization_is_repeatable_without_touching_authorization_metadata(self):
        authorization = Authorization("Lab owner", "AUTH-344-LOOPBACK")
        target = Target("LOCALHOST.", authorization=authorization, labels=("client-metadata",))
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(),
            explicit_networks=(),
            require_authorization_for_public=True,
        )
        authorization_before = (
            authorization.owner,
            authorization.reference,
            authorization.valid_from,
            authorization.valid_until,
        )

        decisions = [policy.decide(target) for _ in range(3)]

        self.assertEqual(decisions, [decisions[0]] * 3)
        self.assertTrue(decisions[0].allowed)
        self.assertEqual(decisions[0].normalized_host, "localhost")
        self.assertEqual(decisions[0].reason, ScopeReason.LOOPBACK)
        self.assertEqual(
            (
                authorization.owner,
                authorization.reference,
                authorization.valid_from,
                authorization.valid_until,
            ),
            authorization_before,
        )


if __name__ == "__main__":
    unittest.main()
