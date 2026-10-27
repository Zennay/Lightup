"""Current-main issue #294 expected-RED policy-collection aliasing acceptance.

Only pure in-memory ScopePolicy calls with fictitious .test hosts and IP
literals. The six @expectedFailure tests are *unresolved installed defects*,
NOT a security pass. No production source, I/O, grants or targets changed.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason


FICTIONAL_AUTH = Authorization(owner="offline-only", reference="NOT-A-REAL-GRANT")


def _host_policy(hosts):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=hosts,
        explicit_networks=(),
        require_authorization_for_public=True,
    )


def _network_policy(networks):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset(),
        explicit_networks=networks,
        require_authorization_for_public=True,
    )


def _decide(policy, host):
    return policy.decide(Target(host, authorization=FICTIONAL_AUTH))


class MutableScopePolicyInputIdentityTests(unittest.TestCase):
    @unittest.expectedFailure
    def test_red_mutable_host_set_must_be_snapshotted_at_construction(self):
        caller_owned = {"fixture.example.test"}
        policy = _host_policy(caller_owned)
        self.assertIs(type(policy.explicit_hosts), frozenset)

    @unittest.expectedFailure
    def test_red_mutable_host_set_must_not_widen_after_construction(self):
        caller_owned = set()
        policy = _host_policy(caller_owned)
        before = _decide(policy, "fixture.example.test")
        self.assertIs(before.allowed, False)
        self.assertIs(before.reason, ScopeReason.OUT_OF_SCOPE)
        caller_owned.add("fixture.example.test")
        after = _decide(policy, "fixture.example.test")
        self.assertIs(after.allowed, False, "caller-owned host set must never mint scope")

    @unittest.expectedFailure
    def test_red_mutable_host_set_must_not_narrow_after_construction(self):
        caller_owned = {"fixture.example.test"}
        policy = _host_policy(caller_owned)
        self.assertIs(_decide(policy, "fixture.example.test").allowed, True)
        caller_owned.clear()
        self.assertIs(_decide(policy, "fixture.example.test").allowed, True)

    @unittest.expectedFailure
    def test_red_mutable_network_list_must_be_snapshotted_at_construction(self):
        caller_owned = ["8.8.8.8/32"]
        policy = _network_policy(caller_owned)
        self.assertIs(type(policy.explicit_networks), tuple)

    @unittest.expectedFailure
    def test_red_mutable_network_list_must_not_widen_after_construction(self):
        caller_owned = []
        policy = _network_policy(caller_owned)
        before = _decide(policy, "8.8.8.8")
        self.assertIs(before.allowed, False)
        self.assertIs(before.reason, ScopeReason.OUT_OF_SCOPE)
        caller_owned.append("8.8.8.8/32")
        after = _decide(policy, "8.8.8.8")
        self.assertIs(after.allowed, False, "caller-owned network list must never mint scope")

    @unittest.expectedFailure
    def test_red_mutable_network_list_must_not_narrow_after_construction(self):
        caller_owned = ["8.8.8.8/32"]
        policy = _network_policy(caller_owned)
        self.assertIs(_decide(policy, "8.8.8.8").allowed, True)
        caller_owned.clear()
        self.assertIs(_decide(policy, "8.8.8.8").allowed, True)

    def test_canonical_frozenset_and_tuple_keep_stable_scope(self):
        hosts = frozenset({"fixture.example.test"})
        networks = ("8.8.8.8/32",)
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=hosts,
            explicit_networks=networks,
            require_authorization_for_public=True,
        )
        for host in ("fixture.example.test", "8.8.8.8"):
            first = _decide(policy, host)
            second = _decide(policy, host)
            self.assertEqual(first, second)
            self.assertIs(first.allowed, True)
        for host in ("other.example.test", "8.8.8.9"):
            self.assertIs(_decide(policy, host).allowed, False)
        self.assertIs(policy.explicit_hosts, hosts)
        self.assertIs(policy.explicit_networks, networks)

    def test_fictitious_authorization_fixture_is_not_global_authority(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"fixture.example.test"}),
            explicit_networks=("8.8.8.8/32",),
            require_authorization_for_public=True,
        )
        for host in ("fixture.example.test", "8.8.8.8"):
            decision = policy.decide(Target(host))
            self.assertIs(decision.allowed, False)
            self.assertIs(decision.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_in_memory_snapshot_review_never_runs_dns_socket_or_process(self):
        policy = _host_policy(frozenset({"fixture.example.test"}))
        target = Target("fixture.example.test", authorization=FICTIONAL_AUTH)
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            decision = policy.decide(target)
        self.assertIs(decision.allowed, True)
        self.assertIs(target.authorization, FICTIONAL_AUTH)


if __name__ == "__main__":
    unittest.main()
