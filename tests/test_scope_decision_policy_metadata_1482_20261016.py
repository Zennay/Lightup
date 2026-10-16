"""#1482 W5: exact metadata snapshot and reason/host kind safety.

All inputs invented in-process. Review-only values do not confer permissions.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation_decision_cohort_review_1482 import review_decision_cohort
from lightup.models import Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


def review(policy, host="localhost", reason=ScopeReason.LOOPBACK, allowed=True):
    t = Target(host)
    d = ScopeDecision(allowed, host, reason)
    return review_decision_cohort(((policy, t, d),))


class PolicyMetadataSnapshotTests(unittest.TestCase):
    def assert_configuration_hold(self, policy):
        verdict = review(policy)
        self.assertEqual((verdict.status, verdict.reason, verdict.inspected),
                         ("HOLD", "invalid_policy_configuration", 0))
        self.assertFalse(verdict.authorizes_execution)

    def test_canonical_frozen_policy_metadata_remains_review_only(self):
        p = ScopePolicy()
        self.assertEqual(review(p).status, "REVIEW_ONLY")

    def test_mutable_host_set_is_hold(self):
        self.assert_configuration_hold(ScopePolicy(explicit_hosts=set()))

    def test_mutable_network_list_is_hold(self):
        self.assert_configuration_hold(ScopePolicy(explicit_networks=[]))

    def test_int_like_private_lab_bool_is_hold(self):
        self.assert_configuration_hold(ScopePolicy(allow_private_lab=1))

    def test_int_like_authorization_requirement_is_hold(self):
        self.assert_configuration_hold(
            ScopePolicy(require_authorization_for_public=0)
        )

    def test_host_string_subclass_is_hold(self):
        class S(str):
            pass
        self.assert_configuration_hold(ScopePolicy(explicit_hosts=frozenset({S("x")})))

    def test_network_string_subclass_is_hold(self):
        class S(str):
            pass
        self.assert_configuration_hold(ScopePolicy(explicit_networks=(S("10.0.0.0/8"),)))

    def test_excess_hosts_are_hold_before_iteration(self):
        self.assert_configuration_hold(
            ScopePolicy(explicit_hosts=frozenset("synthetic-" + str(i) for i in range(65)))
        )

    def test_excess_network_entries_are_hold(self):
        self.assert_configuration_hold(
            ScopePolicy(explicit_networks=("10.0.0.0/8",) * 65)
        )

    def test_oversized_host_entry_is_hold(self):
        self.assert_configuration_hold(
            ScopePolicy(explicit_hosts=frozenset({"z" * 513}))
        )

    def test_erased_original_field_does_not_fall_back_to_default(self):
        p = ScopePolicy()
        object.__delattr__(p, "allow_private_lab")
        self.assert_configuration_hold(p)

    def test_injected_unrecognized_policy_field_is_hold(self):
        p = ScopePolicy()
        object.__setattr__(p, "unexpected", "synthetic")
        self.assert_configuration_hold(p)

    def test_snapshot_copied_not_fetched_fieldwise(self):
        p = ScopePolicy()
        with patch.object(
            ScopePolicy, "allow_private_lab",
            new=property(lambda _: (_ for _ in ()).throw(AssertionError("getter called"))),
            create=True,
        ):
            verdict = review(p)
        self.assertEqual(verdict.status, "REVIEW_ONLY")

    def test_public_domain_cannot_claim_private_lab_reason(self):
        verdict = review(ScopePolicy(), "public.example.test", ScopeReason.PRIVATE_LAB)
        self.assertEqual(verdict.reason, "reason_host_kind_mismatch")
        self.assertEqual(verdict.inspected, 0)

    def test_public_global_ip_cannot_claim_private_lab_reason(self):
        verdict = review(ScopePolicy(), "8.8.8.8", ScopeReason.PRIVATE_LAB)
        self.assertEqual(verdict.reason, "reason_host_kind_mismatch")

    def test_dns_name_cannot_claim_explicit_network(self):
        verdict = review(ScopePolicy(), "public.example.test", ScopeReason.EXPLICIT_NETWORK)
        self.assertEqual(verdict.reason, "reason_host_kind_mismatch")

    def test_ip_literal_cannot_claim_explicit_host(self):
        verdict = review(ScopePolicy(), "8.8.8.8", ScopeReason.EXPLICIT_HOST)
        self.assertEqual(verdict.reason, "reason_host_kind_mismatch")

    def test_real_private_lab_ipv4_still_has_shape_review(self):
        p = ScopePolicy()
        t = Target("10.3.2.1")
        verdict = review_decision_cohort(((p, t, p.decide(t)),))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertFalse(verdict.authorizes_execution)

    def test_real_public_explicit_cidr_remains_non_authorizing(self):
        # Pure synthetic configured CIDR, require_authorization_for_public=False
        # is NOT a safe production choice or proof of customer authorization.
        p = ScopePolicy(explicit_networks=("8.8.8.8/32",),
                        require_authorization_for_public=False)
        t = Target("8.8.8.8")
        d = p.decide(t)
        self.assertEqual(d.reason, ScopeReason.EXPLICIT_NETWORK)
        verdict = review_decision_cohort(((p, t, d),))
        self.assertEqual(verdict.status, "REVIEW_ONLY")
        self.assertFalse(verdict.authorizes_execution)
        self.assertFalse(verdict.authorizes_release)


if __name__ == "__main__":
    unittest.main()
