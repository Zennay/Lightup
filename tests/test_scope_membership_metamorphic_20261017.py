"""Issue #1563: legacy grants cannot manufacture public scope membership.

Pure in-memory, negative-only acceptance. This intentionally does not specify
the positive grant shape (owned by the active scope source owner).
"""

from __future__ import annotations

import os
import sys
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.models import Authorization, Target
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason
from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.orchestrator import AssessmentPlan, Planner


def _grant_variants():
    now = datetime.now(timezone.utc)
    return (
        ("absent", None),
        ("current", Authorization(owner="synthetic-owner", reference="SYN-ONLY")),
        (
            "expired",
            Authorization(
                owner="synthetic-owner",
                reference="SYN-EXPIRED",
                valid_until=now - timedelta(days=1),
            ),
        ),
        (
            "future",
            Authorization(
                owner="synthetic-owner",
                reference="SYN-FUTURE",
                valid_from=now + timedelta(days=1),
            ),
        ),
    )


def _block_all_external_and_grant_admission(stack: ExitStack) -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError(
            "Scope membership rejection must not perform I/O or evaluate grant validity"
        )

    for path in (
        "socket.socket",  # block direct raw socket creation too
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.create_connection",
        "urllib.request.urlopen",
    ):
        stack.enter_context(patch(path, side_effect=unexpected))

    stack.enter_context(patch.object(Authorization, "is_current", unexpected))


class ScopeMembershipMetamorphicTests(unittest.TestCase):
    """Membership-negative fixtures only: no positive grants, execution or targets."""

    def _reject_off_scope(self, policy: ScopePolicy, target: Target, expected_host: str | None = None) -> None:
        before = (target.value, target.authorization, target.labels)
        with ExitStack() as stack:
            _block_all_external_and_grant_admission(stack)
            decision = policy.decide(target)
        self.assertIs(type(decision), ScopeDecision)
        self.assertIs(type(decision.allowed), bool)
        self.assertIs(decision.allowed, False)
        self.assertIs(type(decision.reason), ScopeReason)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)
        self.assertIs(type(decision.normalized_host), str)
        if expected_host is not None:
            self.assertEqual(decision.normalized_host, expected_host)
        self.assertEqual((target.value, target.authorization, target.labels), before)

    def _reject_invalid(self, policy: ScopePolicy, target: Target) -> None:
        before = (target.value, target.authorization, target.labels)
        with ExitStack() as stack:
            _block_all_external_and_grant_admission(stack)
            decision = policy.decide(target)
        self.assertIs(type(decision), ScopeDecision)
        self.assertIs(type(decision.allowed), bool)
        self.assertIs(decision.allowed, False)
        self.assertIs(type(decision.reason), ScopeReason)
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
        self.assertIsNone(decision.normalized_host)
        self.assertEqual((target.value, target.authorization, target.labels), before)

    def test_undeclared_public_hostname_is_invariant_under_grant_substitution(self):
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for value in (
                "unknown.example.test",
                "https://unknown.example.test/limited/path",
                "sub.declared.example.test",
            ):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, value=value, grant=grant_name):
                        self._reject_off_scope(
                            policy,
                            Target(value=value, authorization=grant, labels=("fictional",)),
                        )

    def test_undeclared_public_network_is_invariant_under_grant_substitution(self):
        # 8.8.8.0/24 is declared, 8.8.4.4, 1.1.1.1 and 9.9.9.9 are not.
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for value in ("8.8.4.4", "1.1.1.1", "https://9.9.9.9/"):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, value=value, grant=grant_name):
                        self._reject_off_scope(policy, Target(value, authorization=grant))

    def test_invalid_target_cannot_be_rescued_by_grant_or_auth_flag(self):
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"declared.example.test"}),
                explicit_networks=("8.8.8.0/24",),
                require_authorization_for_public=require_auth,
            )
            for invalid in ("", "  ", "https://", "https:///"):
                for grant_name, grant in _grant_variants():
                    with self.subTest(flag=require_auth, invalid=invalid, grant=grant_name):
                        self._reject_invalid(policy, Target(invalid, authorization=grant))

    def test_unrelated_declared_hosts_cannot_change_membership(self):
        for other in (
            frozenset(),
            frozenset({"allowed.example.test"}),
            frozenset({"allowed.example.test", "other.example.test"}),
        ):
            for require_auth in (True, False):
                for _, grant in _grant_variants():
                    with self.subTest(other=sorted(other), flag=require_auth):
                        self._reject_off_scope(
                            ScopePolicy(
                                allow_private_lab=False,
                                explicit_hosts=other,
                                require_authorization_for_public=require_auth,
                            ),
                            Target("never-declared.example.test", authorization=grant),
                        )

    def test_unrelated_declared_networks_cannot_change_membership(self):
        for networks in ((), ("8.8.8.0/24",), ("8.8.8.0/24", "1.1.1.0/24")):
            for require_auth in (True, False):
                for _, grant in _grant_variants():
                    with self.subTest(networks=networks, flag=require_auth):
                        self._reject_off_scope(
                            ScopePolicy(
                                allow_private_lab=False,
                                explicit_networks=networks,
                                require_authorization_for_public=require_auth,
                            ),
                            Target("9.9.9.9", authorization=grant),
                        )


    def test_public_ipv6_outside_declared_prefix_stays_out_of_scope(self):
        # Actual globally routable Cloudflare-format IPv6 fixture strings;
        # no address is ever contacted, resolved or scanned.
        for allow_private in (True, False):
            for require_auth in (True, False):
                policy = ScopePolicy(
                    allow_private_lab=allow_private,
                    explicit_networks=("2606:4700:4700::2222/128",),
                    require_authorization_for_public=require_auth,
                )
                for value in (
                    "2606:4700:4700::1111",
                    "https://[2606:4700:4700::1111]/",
                ):
                    for name, grant in _grant_variants():
                        with self.subTest(lab=allow_private, flag=require_auth,
                                          value=value, grant=name):
                            self._reject_off_scope(
                                policy, Target(value, authorization=grant)
                            )

    def test_untrusted_authorization_shape_and_label_cannot_mint_membership(self):
        class ExplodingGrant:
            def is_current(self, *_args, **_kwargs):
                raise AssertionError("untrusted grant must not be evaluated")

        for require_auth in (True, False):
            policy = ScopePolicy(
                explicit_hosts=frozenset({"declared.example.test"}),
                require_authorization_for_public=require_auth,
            )
            for labels in (
                ("AUTHORIZED",),
                ("scope:explicit-host", "review:approved"),
                ("synthetic", "risk:low"),
            ):
                with self.subTest(flag=require_auth, labels=labels):
                    self._reject_off_scope(
                        policy,
                        Target(
                            "undeclared.example.test",
                            authorization=ExplodingGrant(),  # type: ignore[arg-type]
                            labels=labels,
                        ),
                    )

    def test_unlisted_subdomain_parent_and_suffix_do_not_inherit_host_grant(self):
        # Never infer wildcards, parents or containment from an explicit hostname.
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"scoped.example.test"}),
                require_authorization_for_public=require_auth,
            )
            for value, canonical in (
                ("untrusted.scoped.example.test", "untrusted.scoped.example.test"),
                ("scoped.example.test.evil.invalid", "scoped.example.test.evil.invalid"),
                ("https://SCOPED.EXAMPLE.TEST.EVIL.INVALID.:443/", "scoped.example.test.evil.invalid"),
            ):
                for name, grant in _grant_variants():
                    for labels in ((), ("AUTHORIZED", "scope:explicit-host")):
                        with self.subTest(value=value, grant=name, flag=require_auth, labels=labels):
                            self._reject_off_scope(
                                policy, Target(value, authorization=grant, labels=labels),
                                expected_host=canonical,
                            )

    def test_ipv4_right_neighbor_of_declared_cidr_remains_unlisted(self):
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=True,
                explicit_networks=("9.9.9.0/28", "1.1.1.0/24"),
                require_authorization_for_public=require_auth,
            )
            for ip in ("9.9.9.16", "9.9.9.17", "9.9.8.255"):
                for name, grant in _grant_variants():
                    with self.subTest(ip=ip, flag=require_auth, grant=name):
                        self._reject_off_scope(
                            policy, Target(ip, authorization=grant), expected_host=ip,
                        )

    def test_ipv6_right_neighbor_of_declared_prefix_remains_unlisted(self):
        # Bracketed URI authorities are deliberately used: unbracketed IPv6
        # parsing and zone-id semantics are owned by separate source issues.
        for require_auth in (True, False):
            policy = ScopePolicy(
                allow_private_lab=True,
                explicit_networks=("2606:4700:4700::/125",),
                require_authorization_for_public=require_auth,
            )
            for value, expected in (
                ("https://[2606:4700:4700::8]/", "2606:4700:4700::8"),
                ("https://[2606:4700:4700::9]/", "2606:4700:4700::9"),
            ):
                for name, grant in _grant_variants():
                    with self.subTest(ip=expected, flag=require_auth, grant=name):
                        self._reject_off_scope(
                            policy, Target(value, authorization=grant), expected_host=expected,
                        )

    def test_generated_global_ipv4_nonmembers_do_not_gain_scope(self):
        # Deterministic, bounded membership oracle: no pseudo-random inputs,
        # DNS, real target access or external host discovery.
        policy = ScopePolicy(
            explicit_networks=("9.9.9.0/28",),
            allow_private_lab=True,
        )
        for final_octet in range(16, 80):
            value = f"9.9.9.{final_octet}"
            for name, grant in _grant_variants():
                with self.subTest(ip=value, grant=name):
                    self._reject_off_scope(
                        policy, Target(value, authorization=grant), expected_host=value,
                    )

    def test_normalized_host_is_not_rebound_to_a_declared_identity(self):
        policy = ScopePolicy(
            explicit_hosts=frozenset({"declared.example.test"}),
            allow_private_lab=False,
        )
        for value, canonical in (
            ("https://UNLISTED.EXAMPLE.TEST.:8443/path", "unlisted.example.test"),
            ("http://mixed.Other.Example.Test/?x=1", "mixed.other.example.test"),
            ("https://DECLARED.EXAMPLE.TEST.EVIL.INVALID/", "declared.example.test.evil.invalid"),
        ):
            for name, grant in _grant_variants():
                with self.subTest(value=value, grant=name):
                    self._reject_off_scope(
                        policy, Target(value, authorization=grant),
                        expected_host=canonical,
                    )

    def test_nonmember_recheck_after_untrusted_grant_replacement_stays_denied(self):
        for require_auth in (True, False):
            for allow_private in (True, False):
                policy = ScopePolicy(
                    allow_private_lab=allow_private,
                    explicit_hosts=frozenset({"declared.example.test"}),
                    explicit_networks=("9.9.9.0/28",),
                    require_authorization_for_public=require_auth,
                )
                for value, canonical in (
                    ("not-declared.example.test", "not-declared.example.test"),
                    ("9.9.9.16", "9.9.9.16"),
                    ("https://[2606:4700:4700::8]/", "2606:4700:4700::8"),
                ):
                    for name, grant in _grant_variants():
                        with self.subTest(host=canonical, grant=name, flag=require_auth, lab=allow_private):
                            self._reject_off_scope(
                                policy, Target(value, authorization=grant, labels=("authorized",)),
                                expected_host=canonical,
                            )


    def test_nonmember_cannot_enter_planner_capability_discovery(self):
        # The planner must deny before even requesting capabilities. A mocked
        # provider is an observation sentinel, never a real adapter/handler.
        for require_auth in (False, True):
            policy = ScopePolicy(
                allow_private_lab=False,
                explicit_hosts=frozenset({"approved.example.test"}),
                explicit_networks=("9.9.9.0/28",),
                require_authorization_for_public=require_auth,
            )
            planner = Planner(policy)
            for name, grant in _grant_variants():
                for value in ("unlisted.example.test", "9.9.9.16", "https://[2606:4700:4700::8]/"):
                    with self.subTest(flag=require_auth, grant=name, value=value):
                        target = Target(value, authorization=grant, labels=("AUTHORIZED",))
                        before = (target.value, target.authorization, target.labels)
                        with ExitStack() as stack:
                            _block_all_external_and_grant_admission(stack)
                            spy = stack.enter_context(patch("lightup.orchestrator.get_capabilities", return_value=()))
                            plan = planner.build(target)
                        self.assertIs(type(plan), AssessmentPlan)
                        self.assertIs(type(plan.scope), ScopeDecision)
                        self.assertIs(type(plan.scope.reason), ScopeReason)
                        self.assertIs(plan.scope.allowed, False)
                        self.assertEqual(plan.scope.reason, ScopeReason.OUT_OF_SCOPE)
                        self.assertEqual(plan.capability_ids, ())
                        self.assertIs(plan.execution_enabled, False)
                        self.assertEqual(plan.target, value)
                        spy.assert_not_called()
                        self.assertEqual((target.value, target.authorization, target.labels), before)

    def test_nonmember_never_reaches_permit_token_creation_in_any_mode(self):
        # Calling the inactive authorization gate must raise before token
        # generation for nonmembers; no permits, handlers or active scans exist.
        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.LAB_ONLY, ActivationMode.AUTHORIZED):
            for require_auth in (False, True):
                policy = ScopePolicy(
                    allow_private_lab=False,
                    explicit_hosts=frozenset({"approved.example.test"}),
                    explicit_networks=("9.9.9.0/28",),
                    require_authorization_for_public=require_auth,
                )
                gate = ActivationGate(
                    policy, ActivationPolicy(mode=mode, activation_reference="SYNTHETIC-NOT-AUTHORITY"),
                )
                for name, grant in _grant_variants():
                    for value in ("unlisted.example.test", "9.9.9.16", "https://[2606:4700:4700::8]/"):
                        with self.subTest(mode=mode.value, flag=require_auth, grant=name, value=value):
                            target = Target(value, authorization=grant, labels=("AUTHORIZED",))
                            before = (target.value, target.authorization, target.labels)
                            with ExitStack() as stack:
                                _block_all_external_and_grant_admission(stack)
                                token_spy = stack.enter_context(
                                    patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC-NEVER-ISSUE")
                                )
                                with self.assertRaisesRegex(PermissionError, "target denied by scope gate"):
                                    gate.issue(target, "fictional-capability-not-registered")
                            token_spy.assert_not_called()
                            self.assertEqual((target.value, target.authorization, target.labels), before)

    def test_invalid_identity_stops_planner_and_permit_before_side_effects(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"approved.example.test"}),
        )
        for value in ("", "   ", "https://", "https:///"):
            for name, grant in _grant_variants():
                with self.subTest(value=value, grant=name):
                    target = Target(value, authorization=grant)
                    with ExitStack() as stack:
                        _block_all_external_and_grant_admission(stack)
                        capabilities = stack.enter_context(
                            patch("lightup.orchestrator.get_capabilities", return_value=())
                        )
                        token = stack.enter_context(
                            patch("lightup.activation.token_urlsafe", return_value="SYNTHETIC-NEVER-ISSUE")
                        )
                        plan = Planner(policy).build(target)
                        self.assertEqual(plan.scope.reason, ScopeReason.INVALID_TARGET)
                        self.assertIs(plan.execution_enabled, False)
                        self.assertEqual(plan.capability_ids, ())
                        capabilities.assert_not_called()
                        for mode in (ActivationMode.PLAN_ONLY, ActivationMode.LAB_ONLY, ActivationMode.AUTHORIZED):
                            with self.subTest(mode=mode.value):
                                gate = ActivationGate(
                                    policy,
                                    ActivationPolicy(
                                        mode=mode, activation_reference="SYNTHETIC-NOT-AUTHORITY"
                                    ),
                                )
                                with self.assertRaisesRegex(PermissionError, "target denied by scope gate"):
                                    gate.issue(target, "fictional-capability-not-registered")
                        token.assert_not_called()


if __name__ == "__main__":
    unittest.main()
