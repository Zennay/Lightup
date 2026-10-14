"""Issue #346: offline monotonic-narrowing contract for legacy ScopePolicy.

Tests only. This does not authorize targets or repair the installed executor.
"""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import replace
from itertools import combinations
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


HOSTS = frozenset(("alpha.example", "beta.example"))
NETWORKS = ("8.8.8.0/24", "1.1.1.0/24", "2001:4860:4860::/48")
AUTH = Authorization(owner="synthetic-owner", reference="LAB-ONLY-NOT-CONSENT")
TARGETS = (
    Target("alpha.example"),
    Target("https://ALPHA.EXAMPLE./path"),
    Target("beta.example"),
    Target("alpha.example", authorization=AUTH),
    Target("8.8.8.8"),
    Target("8.8.8.8", authorization=AUTH),
    Target("1.1.1.1"),
    Target("https://[2001:4860:4860::8888]/status"),
    Target("[2001:4860:4860::8888]", authorization=AUTH),
    Target("10.6.7.8"),
    Target("http://[fd00::1234]/"),
    Target("169.254.2.3"),
    Target("127.0.0.1"),
    Target("http://[::1]/"),
    Target("localhost"),
    Target("9.9.9.9"),
    Target("unlisted.example"),
)


def _subsets(items):
    return tuple(
        combination
        for count in range(len(items) + 1)
        for combination in combinations(items, count)
    )


def _policies():
    """Enumerate 128 canonical policies: all subset and switch combinations."""
    for host_set in _subsets(tuple(sorted(HOSTS))):
        for networks in _subsets(NETWORKS):
            for allow_lab in (False, True):
                for require_auth in (False, True):
                    yield ScopePolicy(
                        allow_private_lab=allow_lab,
                        explicit_hosts=frozenset(host_set),
                        explicit_networks=networks,
                        require_authorization_for_public=require_auth,
                    )


def _is_narrower(candidate: ScopePolicy, baseline: ScopePolicy) -> bool:
    return (
        candidate.explicit_hosts <= baseline.explicit_hosts
        and set(candidate.explicit_networks) <= set(baseline.explicit_networks)
        and (not candidate.allow_private_lab or baseline.allow_private_lab)
        and (candidate.require_authorization_for_public or not baseline.require_authorization_for_public)
    )


class ScopeNarrowingMatrixTests(unittest.TestCase):
    def test_full_pairwise_narrowing_cannot_turn_denial_into_allow(self):
        policies = tuple(_policies())
        self.assertEqual(len(policies), 128)
        before = {
            policy: tuple(policy.decide(target) for target in TARGETS)
            for policy in policies
        }
        comparisons = 0
        for baseline in policies:
            for candidate in policies:
                if not _is_narrower(candidate, baseline):
                    continue
                comparisons += 1
                for index, target in enumerate(TARGETS):
                    original = before[baseline][index]
                    narrowed = before[candidate][index]
                    with self.subTest(baseline=baseline, narrowed=candidate, target=target.value):
                        self.assertEqual(narrowed.normalized_host, original.normalized_host)
                        self.assertFalse(
                            narrowed.allowed and not original.allowed,
                            f"narrowing increased scope: {original!r} -> {narrowed!r}",
                        )
        self.assertGreater(comparisons, 100)
        for policy in policies:
            self.assertEqual(
                tuple(policy.decide(target) for target in TARGETS),
                before[policy],
                "ScopePolicy.decide mutated policy state or leaked decision state",
            )

    def test_removing_explicit_host_only_withdraws_its_authority(self):
        broad = ScopePolicy(
            explicit_hosts=HOSTS, require_authorization_for_public=False
        )
        narrow = replace(broad, explicit_hosts=frozenset(("beta.example",)))
        self.assertEqual(broad.decide(Target("alpha.example")).reason, ScopeReason.EXPLICIT_HOST)
        denied = narrow.decide(Target("alpha.example"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(narrow.decide(Target("beta.example")).reason, ScopeReason.EXPLICIT_HOST)

    def test_removing_explicit_network_only_withdraws_its_authority(self):
        broad = ScopePolicy(
            explicit_networks=NETWORKS, require_authorization_for_public=False
        )
        narrow = replace(broad, explicit_networks=("1.1.1.0/24",))
        self.assertEqual(broad.decide(Target("8.8.8.8")).reason, ScopeReason.EXPLICIT_NETWORK)
        denied = narrow.decide(Target("8.8.8.8"))
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(narrow.decide(Target("1.1.1.1")).reason, ScopeReason.EXPLICIT_NETWORK)

    def test_ipv6_public_network_withdrawal_retains_ipv4_networks(self):
        broad = ScopePolicy(
            explicit_networks=NETWORKS,
            require_authorization_for_public=False,
        )
        narrow = replace(
            broad, explicit_networks=("8.8.8.0/24", "1.1.1.0/24")
        )
        ipv6_target = Target("https://[2001:4860:4860::8888]/status")
        original = broad.decide(ipv6_target)
        denied = narrow.decide(ipv6_target)
        self.assertTrue(original.allowed)
        self.assertEqual(original.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertEqual(denied.normalized_host, original.normalized_host)
        self.assertEqual(
            narrow.decide(Target("8.8.8.8")).reason,
            ScopeReason.EXPLICIT_NETWORK,
        )

    def test_switching_to_require_public_authorization_rejects_both_kinds(self):
        broad = ScopePolicy(
            explicit_hosts=HOSTS,
            explicit_networks=NETWORKS,
            require_authorization_for_public=False,
        )
        narrow = replace(broad, require_authorization_for_public=True)
        for name in ("alpha.example", "8.8.8.8", "https://[2001:4860:4860::8888]/"):
            with self.subTest(name=name):
                self.assertTrue(broad.decide(Target(name)).allowed)
                denied = narrow.decide(Target(name))
                self.assertFalse(denied.allowed)
                self.assertEqual(denied.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_valid_synthetic_auth_keeps_existing_scope_not_new_scope(self):
        narrow = ScopePolicy(
            explicit_hosts=frozenset(("alpha.example",)),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
            allow_private_lab=False,
        )
        self.assertEqual(narrow.decide(Target("alpha.example", AUTH)).reason, ScopeReason.EXPLICIT_HOST)
        self.assertEqual(narrow.decide(Target("8.8.8.8", AUTH)).reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertFalse(narrow.decide(Target("beta.example", AUTH)).allowed)
        self.assertFalse(narrow.decide(Target("1.1.1.1", AUTH)).allowed)

    def test_disabling_private_lab_never_adds_private_authority(self):
        broad = ScopePolicy(allow_private_lab=True)
        narrow = replace(broad, allow_private_lab=False)
        for value in ("10.6.7.8", "169.254.2.3", "http://[fd00::1234]/"):
            with self.subTest(value=value):
                self.assertEqual(broad.decide(Target(value)).reason, ScopeReason.PRIVATE_LAB)
                denied = narrow.decide(Target(value))
                self.assertFalse(denied.allowed)
                self.assertEqual(denied.reason, ScopeReason.OUT_OF_SCOPE)

    def test_loopback_baseline_preserved_not_promoted_to_public(self):
        broad = ScopePolicy(
            allow_private_lab=True,
            explicit_hosts=HOSTS,
            explicit_networks=NETWORKS,
            require_authorization_for_public=False,
        )
        narrow = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(),
            explicit_networks=(),
            require_authorization_for_public=True,
        )
        for value in ("localhost", "127.0.0.1", "http://[::1]/"):
            self.assertEqual(broad.decide(Target(value)).reason, ScopeReason.LOOPBACK)
            self.assertEqual(narrow.decide(Target(value)).reason, ScopeReason.LOOPBACK)

    def test_unlisted_public_targets_remain_denied_across_switches(self):
        for policy in _policies():
            for value in ("9.9.9.9", "unlisted.example"):
                with self.subTest(policy=policy, value=value):
                    decision = policy.decide(Target(value, AUTH))
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_policy_target_and_results_unchanged_after_denials(self):
        initial = ScopePolicy(
            allow_private_lab=True,
            explicit_hosts=HOSTS,
            explicit_networks=NETWORKS,
            require_authorization_for_public=False,
        )
        target = Target("https://ALPHA.EXAMPLE./path", labels=("not-a-grant",))
        stable_policy = (
            initial.allow_private_lab,
            initial.explicit_hosts,
            initial.explicit_networks,
            initial.require_authorization_for_public,
        )
        stable_target = (target.value, target.authorization, target.labels)
        baseline = initial.decide(target)
        for candidate in (
            replace(initial, explicit_hosts=frozenset()),
            replace(initial, require_authorization_for_public=True),
            replace(initial, allow_private_lab=False),
        ):
            candidate.decide(target)
        self.assertEqual(initial.decide(target), baseline)
        self.assertEqual(
            (initial.allow_private_lab, initial.explicit_hosts,
             initial.explicit_networks, initial.require_authorization_for_public),
            stable_policy,
        )
        self.assertEqual((target.value, target.authorization, target.labels), stable_target)

    def test_contract_uses_no_dns_or_network(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("socket.socket", side_effect=AssertionError("socket forbidden")):
            for policy in _policies():
                for target in TARGETS:
                    policy.decide(target)


if __name__ == "__main__":
    unittest.main()
