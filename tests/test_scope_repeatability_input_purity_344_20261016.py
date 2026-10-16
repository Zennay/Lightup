"""Issue #344: real ScopePolicy.decide deterministic, input-pure offline contracts.

Fabricated fixtures only. No authorization or active handler is issued.
"""
from __future__ import annotations

from dataclasses import fields
from itertools import product
from random import Random

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


START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2099, 1, 1, tzinfo=timezone.utc)
PAST = datetime(2021, 1, 1, tzinfo=timezone.utc)


def grant(kind: str) -> Authorization | None:
    if kind == "none":
        return None
    if kind == "current":
        return Authorization(
            owner="Offline fictional owner",
            reference="SYNTHETIC-344-ONLY",
            valid_from=START, valid_until=END,
        )
    if kind == "expired":
        return Authorization(
            owner="Offline fictional owner",
            reference="EXPIRED-344-ONLY",
            valid_from=START, valid_until=PAST,
        )
    raise AssertionError("invalid fixed fixture")


def scenarios() -> tuple[tuple[ScopePolicy, Target], ...]:
    policies = (
        ScopePolicy(allow_private_lab=False),
        ScopePolicy(allow_private_lab=True),
        ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        ),
        ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=False,
        ),
    )
    hosts = (
        "localhost", "127.0.0.1", "10.44.3.5", "8.8.8.8",
        "review.example.test", "elsewhere.example.test",
        "REVIEW.EXAMPLE.TEST", "",
    )
    return tuple(
        (policy, Target(host, grant(grant_kind), ("synthetic", grant_kind)))
        for policy, host, grant_kind in product(
            policies, hosts, ("none", "current", "expired")
        )
    )


def original_values(policy: ScopePolicy, target: Target) -> tuple[object, ...]:
    authorization = target.authorization
    return (
        id(policy), tuple(getattr(policy, f.name) for f in fields(policy)),
        id(target), tuple(getattr(target, f.name) for f in fields(target)),
        None if authorization is None else id(authorization),
        None if authorization is None else
        tuple(getattr(authorization, f.name) for f in fields(authorization)),
    )


class ScopeReplayMatrix344Tests(unittest.TestCase):
    def test_seeded_matrix_has_96_distinct_scenario_positions(self):
        cases = scenarios()
        self.assertEqual(len(cases), 96)
        self.assertEqual(len({(id(p), t.value, t.labels) for p, t in cases}), 96)

    def test_96_canonical_scenarios_repeat_32_times(self):
        cases = scenarios()
        expected = tuple(policy.decide(target) for policy, target in cases)
        originals = tuple(original_values(policy, target) for policy, target in cases)
        for _ in range(32):
            self.assertEqual(tuple(p.decide(t) for p, t in cases), expected)
        self.assertEqual(
            tuple(original_values(p, t) for p, t in cases), originals
        )

    def test_96_canonical_scenarios_order_independent_64_shuffles(self):
        cases = scenarios()
        originals = tuple(original_values(p, t) for p, t in cases)
        baseline = tuple(p.decide(t) for p, t in cases)
        indices = list(range(len(cases)))
        rng = Random(344)
        for _ in range(64):
            rng.shuffle(indices)
            for index in indices:
                policy, target = cases[index]
                self.assertEqual(policy.decide(target), baseline[index])
        self.assertEqual(
            tuple(original_values(p, t) for p, t in cases), originals
        )

    def test_no_persistent_state_contamination_between_a_and_b(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            require_authorization_for_public=True,
        )
        a = Target("review.example.test", grant("current"))
        b = Target("review.example.test", grant("expired"))
        c = Target("elsewhere.example.test", grant("current"))
        baseline = tuple(policy.decide(t) for t in (a, b, c))
        self.assertEqual(tuple(x.reason for x in baseline), (
            ScopeReason.EXPLICIT_HOST, ScopeReason.AUTHORIZATION_EXPIRED,
            ScopeReason.OUT_OF_SCOPE,
        ))
        for _ in range(256):
            self.assertEqual(policy.decide(b), baseline[1])
            self.assertEqual(policy.decide(a), baseline[0])
            self.assertEqual(policy.decide(c), baseline[2])
        self.assertEqual(a.authorization.reference, "SYNTHETIC-344-ONLY")
        self.assertEqual(b.authorization.reference, "EXPIRED-344-ONLY")

    def test_exact_scope_allow_and_deny_canaries_not_only_relative_equality(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        valid = grant("current")
        tests = (
            (Target("review.example.test", valid), True, ScopeReason.EXPLICIT_HOST),
            (Target("review.example.test"), False, ScopeReason.AUTHORIZATION_MISSING),
            (Target("review.example.test", grant("expired")),
             False, ScopeReason.AUTHORIZATION_EXPIRED),
            (Target("8.8.8.8", valid), True, ScopeReason.EXPLICIT_NETWORK),
            (Target("8.8.8.8"), False, ScopeReason.AUTHORIZATION_MISSING),
            (Target("elsewhere.example.test", valid), False, ScopeReason.OUT_OF_SCOPE),
            (Target("localhost"), True, ScopeReason.LOOPBACK),
        )
        for target, allowed, reason in tests:
            with self.subTest(target=target.value, reason=reason.value):
                result = policy.decide(target)
                self.assertIs(type(result), ScopeDecision)
                self.assertIs(type(result.allowed), bool)
                self.assertIs(result.allowed, allowed)
                self.assertIs(result.reason, reason)

    def test_case_normalization_independent_of_prior_uppercase_request(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test",)),
        )
        auth = grant("current")
        variants = tuple(Target(value, auth, ("synthetic",)) for value in (
            "review.example.test", "REVIEW.EXAMPLE.TEST", "Review.Example.Test"
        ))
        results = tuple(policy.decide(v) for v in variants)
        self.assertEqual(len(set(results)), 1)
        for _ in range(32):
            self.assertEqual(tuple(policy.decide(v) for v in reversed(variants)),
                             tuple(reversed(results)))
        self.assertEqual(variants[1].value, "REVIEW.EXAMPLE.TEST")

    def test_explicit_network_tuple_and_host_frozenset_preserved(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset(("review.example.test", "other.example.test")),
            explicit_networks=("8.8.8.0/24", "9.9.9.0/24"),
            require_authorization_for_public=True,
        )
        before = original_values(policy, Target("8.8.8.8", grant("current")))
        target = Target("8.8.8.8", grant("current"))
        p_before = tuple(getattr(policy, f.name) for f in fields(policy))
        for _ in range(64):
            self.assertTrue(policy.decide(target).allowed)
            self.assertFalse(policy.decide(Target("8.8.8.8")).allowed)
        self.assertEqual(
            tuple(getattr(policy, f.name) for f in fields(policy)), p_before
        )
        self.assertEqual(policy.explicit_networks,
                         ("8.8.8.0/24", "9.9.9.0/24"))
        self.assertEqual(policy.explicit_hosts,
                         frozenset(("review.example.test", "other.example.test")))

    def test_fresh_equivalent_canonical_objects_identical_decisions(self):
        for a_policy, a_target in scenarios():
            b_policy = ScopePolicy(
                allow_private_lab=a_policy.allow_private_lab,
                explicit_hosts=frozenset(a_policy.explicit_hosts),
                explicit_networks=tuple(a_policy.explicit_networks),
                require_authorization_for_public=a_policy.require_authorization_for_public,
            )
            b_auth = a_target.authorization
            if b_auth is not None:
                b_auth = Authorization(
                    owner=b_auth.owner, reference=b_auth.reference,
                    valid_from=b_auth.valid_from, valid_until=b_auth.valid_until,
                )
            b_target = Target(a_target.value, b_auth, tuple(a_target.labels))
            self.assertEqual(a_policy.decide(a_target),
                             b_policy.decide(b_target))

    def test_seeded_replay_does_not_access_network_or_process(self):
        cases = scenarios()
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(socket, "gethostbyname", side_effect=AssertionError("dns")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            baseline = tuple(p.decide(t) for p, t in cases)
            for _ in range(8):
                self.assertEqual(tuple(p.decide(t) for p, t in cases), baseline)

    def test_canonical_fixture_does_not_ever_create_permit_or_grant(self):
        for policy, target in scenarios():
            decision = policy.decide(target)
            self.assertIs(type(decision), ScopeDecision)
            self.assertEqual(set(vars(decision)), {
                "allowed", "normalized_host", "reason"
            })
            self.assertFalse(hasattr(decision, "permit"))
            self.assertFalse(hasattr(decision, "activation_reference"))


if __name__ == "__main__":
    unittest.main()
