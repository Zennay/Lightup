"""Issue #344: real ScopePolicy.decide deterministic, input-pure offline contracts.

Fabricated fixtures only. No authorization or active handler is issued.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
import socket
import subprocess
import unittest
from unittest.mock import patch
from urllib import request as urllib_request

from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason


FROM = datetime(2020, 1, 1, tzinfo=timezone.utc)
UNTIL = datetime(2099, 1, 1, tzinfo=timezone.utc)


def canonical_auth() -> Authorization:
    return Authorization(
        owner="Fictional test owner",
        reference="SYNTHETIC-344",
        valid_from=FROM,
        valid_until=UNTIL,
    )


def originals(target: Target, policy: ScopePolicy) -> tuple[object, ...]:
    """Capture original references and exact content, without stringification."""
    grant = target.authorization
    return (
        target, target.value, target.labels, grant,
        None if grant is None else grant.owner,
        None if grant is None else grant.reference,
        None if grant is None else grant.valid_from,
        None if grant is None else grant.valid_until,
        policy, policy.allow_private_lab, policy.explicit_hosts,
        policy.explicit_networks, policy.require_authorization_for_public,
    )


class ScopeRepeatabilityAndPurity344Tests(unittest.TestCase):
    def assertPureReplay(
        self, policy: ScopePolicy, target: Target,
        allowed: bool, reason: ScopeReason, host: str | None,
    ) -> ScopeDecision:
        before = originals(target, policy)
        prior = policy.decide(target)
        self.assertIs(type(prior), ScopeDecision)
        self.assertIs(type(prior.allowed), bool)
        self.assertIs(prior.allowed, allowed)
        self.assertIs(prior.reason, reason)
        self.assertEqual(prior.normalized_host, host)
        for _ in range(32):
            self.assertEqual(policy.decide(target), prior)
            self.assertEqual(originals(target, policy), before)
        self.assertEqual(originals(target, policy), before)
        self.assertIs(target, before[0])
        self.assertIs(policy, before[8])
        self.assertIs(target.authorization, before[3])
        return prior

    def test_loopback_repeatable_and_input_pure(self):
        self.assertPureReplay(
            ScopePolicy(), Target("localhost", labels=("lab", "synthetic")),
            True, ScopeReason.LOOPBACK, "localhost",
        )

    def test_ipv4_loopback_same_outcome(self):
        self.assertPureReplay(
            ScopePolicy(allow_private_lab=False), Target("127.0.0.1"),
            True, ScopeReason.LOOPBACK, "127.0.0.1",
        )

    def test_private_lab_toggle_true(self):
        self.assertPureReplay(
            ScopePolicy(allow_private_lab=True), Target("10.23.1.2"),
            True, ScopeReason.PRIVATE_LAB, "10.23.1.2",
        )

    def test_private_lab_toggle_false(self):
        self.assertPureReplay(
            ScopePolicy(allow_private_lab=False), Target("10.23.1.2"),
            False, ScopeReason.OUT_OF_SCOPE, "10.23.1.2",
        )

    def test_public_explicit_host_current_authorization_is_pure(self):
        scope = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            require_authorization_for_public=True,
        )
        target = Target("review.example.test", canonical_auth(),
                        ("owner-consent-fixture-only", "synthetic"))
        self.assertPureReplay(scope, target, True, ScopeReason.EXPLICIT_HOST,
                              "review.example.test")
        self.assertEqual(scope.explicit_hosts, frozenset(("review.example.test",)))
        self.assertEqual(target.labels, ("owner-consent-fixture-only", "synthetic"))

    def test_public_explicit_ipv4_network_current_authorization_is_pure(self):
        scope = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.0/24", "9.9.9.0/24"),
            require_authorization_for_public=True,
        )
        target = Target("8.8.8.8", canonical_auth(), ("synthetic",))
        self.assertPureReplay(scope, target, True, ScopeReason.EXPLICIT_NETWORK,
                              "8.8.8.8")
        self.assertEqual(scope.explicit_networks, ("8.8.8.0/24", "9.9.9.0/24"))

    def test_explicit_host_missing_grant_stably_denied(self):
        scope = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            require_authorization_for_public=True,
        )
        self.assertPureReplay(scope, Target("review.example.test", labels=("no-grant",)),
                              False, ScopeReason.AUTHORIZATION_MISSING,
                              "review.example.test")

    def test_explicit_network_missing_grant_stably_denied(self):
        scope = ScopePolicy(
            allow_private_lab=False, explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        self.assertPureReplay(scope, Target("8.8.8.8"),
                              False, ScopeReason.AUTHORIZATION_MISSING, "8.8.8.8")

    def test_expired_grant_stays_expired_and_unchanged(self):
        expired = Authorization(
            owner="Fictional test owner", reference="EXPIRED-SYNTHETIC",
            valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
            valid_until=datetime(2021, 1, 1, tzinfo=timezone.utc),
        )
        scope = ScopePolicy(allow_private_lab=False,
                            explicit_hosts=frozenset(("expired.example.test",)))
        self.assertPureReplay(scope, Target("expired.example.test", expired),
                              False, ScopeReason.AUTHORIZATION_EXPIRED,
                              "expired.example.test")

    def test_out_of_scope_name_stably_denied(self):
        self.assertPureReplay(
            ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset(
                ("allowed.example.test",))),
            Target("unknown.example.test", canonical_auth(), ("untrusted",)),
            False, ScopeReason.OUT_OF_SCOPE, "unknown.example.test",
        )

    def test_invalid_empty_target_repeated(self):
        self.assertPureReplay(
            ScopePolicy(allow_private_lab=False), Target(""),
            False, ScopeReason.INVALID_TARGET, None,
        )

    def test_case_normalization_does_not_mutate_target_value(self):
        scope = ScopePolicy(allow_private_lab=False,
                            explicit_hosts=frozenset(("review.example.test",)))
        target = Target("REVIEW.Example.Test", canonical_auth(), ("preserve",))
        self.assertPureReplay(scope, target, True, ScopeReason.EXPLICIT_HOST,
                              "review.example.test")
        self.assertEqual(target.value, "REVIEW.Example.Test")

    def test_repeatability_across_interleaved_different_inputs(self):
        scope = ScopePolicy(allow_private_lab=False,
                            explicit_hosts=frozenset(("review.example.test",)))
        approved = Target("review.example.test", canonical_auth())
        unapproved = Target("other.example.test", canonical_auth())
        approved_before = originals(approved, scope)
        unapproved_before = originals(unapproved, scope)
        first = scope.decide(approved)
        denied = scope.decide(unapproved)
        for _ in range(48):
            self.assertEqual(scope.decide(unapproved), denied)
            self.assertEqual(scope.decide(approved), first)
        self.assertTrue(first.allowed)
        self.assertFalse(denied.allowed)
        self.assertEqual(originals(approved, scope), approved_before)
        self.assertEqual(originals(unapproved, scope), unapproved_before)

    def test_no_network_dns_http_process_or_shell_during_real_decisions(self):
        scope = ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset(
            ("review.example.test",)), explicit_networks=("8.8.8.0/24",))
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(socket, "gethostbyname", side_effect=AssertionError("dns")), \
             patch.object(urllib_request, "urlopen", side_effect=AssertionError("http")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch.object(os, "system", side_effect=AssertionError("shell")):
            self.assertPureReplay(scope, Target("review.example.test", canonical_auth()),
                                  True, ScopeReason.EXPLICIT_HOST, "review.example.test")
            self.assertPureReplay(scope, Target("8.8.8.8", canonical_auth()),
                                  True, ScopeReason.EXPLICIT_NETWORK, "8.8.8.8")
            self.assertPureReplay(scope, Target("unknown.example.test"),
                                  False, ScopeReason.OUT_OF_SCOPE,
                                  "unknown.example.test")


if __name__ == "__main__":
    unittest.main()
