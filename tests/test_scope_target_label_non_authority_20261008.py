"""Target labels are display metadata, never scope or consent authority.

Offline-only regression: no DNS, sockets, handlers, scans, or capability dispatch.
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


class TargetLabelNonAuthorityTests(unittest.TestCase):
    def test_claimed_approval_labels_cannot_approve_public_host(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        for labels in (
            ("approved",),
            ("consent:true", "risk:low"),
            ("tenant:owner", "authorization:current"),
            ("scope:approved.example.test", "admin-reviewed"),
        ):
            with self.subTest(labels=labels):
                decision = policy.decide(Target("approved.example.test", labels=labels))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_labels_cannot_expand_unknown_host_scope_even_with_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        authorization = Authorization(owner="owner", reference="AUTH-LABELS")
        for labels in ((), ("approved",), ("scope:unknown.example.test",)):
            with self.subTest(labels=labels):
                decision = policy.decide(Target(
                    "unknown.example.test", authorization=authorization, labels=labels
                ))
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_labels_cannot_revive_expired_public_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        expired = Authorization(
            owner="owner", reference="AUTH-EXPIRED",
            valid_until=datetime.now(timezone.utc) - timedelta(days=1),
        )
        decision = policy.decide(Target(
            "approved.example.test", authorization=expired,
            labels=("reapproved", "valid_until:never", "consent:true"),
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_labels_do_not_change_valid_public_authorization_decision(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        authorization = Authorization(owner="owner", reference="AUTH-VALID")
        baseline = policy.decide(Target("approved.example.test", authorization=authorization))
        labeled = policy.decide(Target(
            "approved.example.test", authorization=authorization,
            labels=("not-approved", "risk:critical"),
        ))
        self.assertEqual(baseline, labeled)
        self.assertTrue(labeled.allowed)
        self.assertEqual(labeled.reason, ScopeReason.EXPLICIT_HOST)

    def test_claimed_approval_labels_cannot_authorize_public_ip(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24",),
        )
        decision = policy.decide(Target(
            "8.8.8.8", labels=("approved", "tenant:owner"),
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_MISSING)


    def test_labels_cannot_expand_unknown_public_ip_network(self):
        policy = ScopePolicy(
            allow_private_lab=False, explicit_networks=("8.8.8.0/24",),
        )
        authorization = Authorization(owner="owner", reference="AUTH-NET")
        decision = policy.decide(Target(
            "9.9.9.9", authorization=authorization,
            labels=("scope:9.9.9.0/24", "approved"),
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_labels_cannot_activate_future_public_authorization(self):
        policy = ScopePolicy(explicit_hosts=frozenset({"approved.example.test"}))
        future = Authorization(
            owner="owner", reference="AUTH-FUTURE",
            valid_from=datetime.now(timezone.utc) + timedelta(days=1),
        )
        decision = policy.decide(Target(
            "approved.example.test", authorization=future,
            labels=("approved-now", "valid_from:yesterday"),
        ))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_labels_do_not_change_valid_explicit_network_decision(self):
        policy = ScopePolicy(
            allow_private_lab=False, explicit_networks=("8.8.8.0/24",),
        )
        authorization = Authorization(owner="owner", reference="AUTH-NET")
        baseline = policy.decide(Target("8.8.8.8", authorization=authorization))
        labeled = policy.decide(Target(
            "8.8.8.8", authorization=authorization,
            labels=("denied", "risk:critical", "scope:unknown.example.test"),
        ))
        self.assertEqual(baseline, labeled)
        self.assertTrue(labeled.allowed)
        self.assertEqual(labeled.reason, ScopeReason.EXPLICIT_NETWORK)

if __name__ == "__main__":
    unittest.main()
