"""#299 owner-portable installed-source provenance contract: main and PR #100.

These synthetic assertions work whether legacy Authorization already has the
owner-managed assets/revocation fields. Assets are explicitly attached only
when the *installed* source supports them, never forged/ignored to fake a PASS.
This test pack must not be used as customer consent or branch attestation.
"""
from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timedelta, timezone
import os
import sys
import unittest
from unittest import mock


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.activation import ActivationGate, ActivationPolicy, ActivationMode


HOST = "review.example.test"
IP = "203.0.113.27"
CAPABILITY = "no-execution-fictitious"
_OPERATOR = "FICTIONAL-OPERATOR-NOT-A-GRANT"
_CLIENT = "FICTIONAL-CLIENT-NOT-A-GRANT"


def _supports_assets() -> bool:
    return "assets" in {f.name for f in fields(Authorization)}


def _grant(host: str, owner: object = "fictional-owner",
           reference: object = _CLIENT) -> Authorization:
    extras = {"assets": (host,)} if _supports_assets() else {}
    return Authorization(owner=owner, reference=reference, **extras)


def _policy(host: str) -> ScopePolicy:
    if host == HOST:
        return ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({HOST}))
    return ScopePolicy(allow_private_lab=False, explicit_networks=("203.0.113.0/24",))


class SourceOwnerPortable299Tests(unittest.TestCase):
    def setUp(self):
        for name in ("socket", "create_connection", "getaddrinfo",
                     "gethostbyname", "gethostbyname_ex"):
            patcher = mock.patch(
                "socket." + name,
                side_effect=AssertionError("#299 installed-source pack forbids DNS/network"),
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_canonical_host_grant_preserves_owner_asset_contract(self):
        auth = _grant(HOST)
        result = _policy(HOST).decide(Target(HOST, authorization=auth))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_HOST)
        if _supports_assets():
            self.assertEqual(auth.assets, (HOST,))
            self.assertTrue(auth.allows_asset(HOST))
        else:
            self.assertNotIn("assets", {f.name for f in fields(Authorization)})

    def test_canonical_network_grant_preserves_owner_asset_contract(self):
        auth = _grant(IP)
        result = _policy(IP).decide(Target(IP, authorization=auth))
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)
        if _supports_assets():
            self.assertEqual(auth.assets, (IP,))
            self.assertTrue(auth.allows_asset(IP))

    def test_missing_client_grant_stays_denied_without_operator(self):
        for host in (HOST, IP):
            with self.subTest(host=host):
                result = _policy(host).decide(Target(host))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_MISSING)

    def test_expired_client_grant_stays_denied_on_both_source_shapes(self):
        for host in (HOST, IP):
            with self.subTest(host=host):
                current = _grant(host)
                extras = {"assets": (host,)} if _supports_assets() else {}
                expired = Authorization(
                    owner=current.owner, reference=current.reference,
                    valid_until=datetime.now(timezone.utc) - timedelta(days=1),
                    **extras,
                )
                result = _policy(host).decide(Target(host, authorization=expired))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_EXPIRED)

    def test_lab_only_loopback_does_not_mint_client_provenance(self):
        gate = ActivationGate(
            _policy(HOST), ActivationPolicy(mode=ActivationMode.LAB_ONLY),
        )
        target = Target("localhost")
        permit = gate.issue(target, CAPABILITY)
        self.assertEqual(permit.target, "localhost")
        self.assertIs(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.activation_reference, "LAB")
        self.assertIsNone(getattr(permit, "authorization_reference", None))
        self.assertIsNone(target.authorization)

    def test_canonical_authorized_host_keeps_distinct_operator_reference(self):
        gate = ActivationGate(
            _policy(HOST),
            ActivationPolicy(mode=ActivationMode.AUTHORIZED,
                             activation_reference=_OPERATOR),
        )
        target = Target(HOST, authorization=_grant(HOST))
        permit = gate.issue(target, CAPABILITY)  # no handler, only in-memory data
        self.assertEqual(permit.target, HOST)
        self.assertEqual(permit.activation_reference, _OPERATOR)
        self.assertEqual(target.authorization.reference, _CLIENT)
        if "authorization_reference" in {f.name for f in fields(type(permit))}:
            # PR #100 owns this separate field, missing on current main.
            self.assertEqual(permit.authorization_reference, _CLIENT)
        else:
            self.assertFalse(hasattr(permit, "authorization_reference"))

    def test_installed_policy_and_grant_objects_are_not_mutated(self):
        grant = _grant(HOST)
        policy = _policy(HOST)
        original = (
            grant.owner, grant.reference, grant.valid_from, grant.valid_until,
            getattr(grant, "assets", None),
        )
        decision = policy.decide(Target(HOST, grant))
        self.assertTrue(decision.allowed)
        self.assertEqual(
            (grant.owner, grant.reference, grant.valid_from, grant.valid_until,
             getattr(grant, "assets", None)),
            original,
        )

    @unittest.expectedFailure
    def test_red_blank_client_owner_must_not_admit_bound_public_host(self):
        self.assertFalse(
            _policy(HOST).decide(Target(HOST, _grant(HOST, owner=""))).allowed
        )

    @unittest.expectedFailure
    def test_red_blank_client_reference_must_not_admit_bound_public_network(self):
        self.assertFalse(
            _policy(IP).decide(Target(IP, _grant(IP, reference=""))).allowed
        )

    @unittest.expectedFailure
    def test_red_whitespace_owner_must_not_admit_bound_public_host(self):
        self.assertFalse(
            _policy(HOST).decide(Target(HOST, _grant(HOST, owner=" \t "))).allowed
        )

    @unittest.expectedFailure
    def test_red_padded_reference_must_not_admit_bound_public_network(self):
        self.assertFalse(
            _policy(IP).decide(Target(IP, _grant(IP, reference=" " + _CLIENT))).allowed
        )

    @unittest.expectedFailure
    def test_red_none_owner_must_not_admit_bound_public_host(self):
        self.assertFalse(
            _policy(HOST).decide(Target(HOST, _grant(HOST, owner=None))).allowed
        )

    @unittest.expectedFailure
    def test_red_bool_reference_must_not_admit_bound_public_network(self):
        self.assertFalse(
            _policy(IP).decide(Target(IP, _grant(IP, reference=True))).allowed
        )

    @unittest.expectedFailure
    def test_red_current_legacy_grant_must_require_canonical_owner(self):
        self.assertFalse(_grant(HOST, owner="").is_current())

    @unittest.expectedFailure
    def test_red_current_legacy_grant_must_require_canonical_reference(self):
        self.assertFalse(_grant(IP, reference="").is_current())


class SourceOwnerPortable299Oracle(unittest.TestCase):
    def test_portable_source_debt_oracle_identifies_eight_real_open_gaps(self):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SourceOwnerPortable299Tests)
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, 15)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.failures, [])
        self.assertEqual(result.skipped, [])
        self.assertEqual(result.unexpectedSuccesses, [])
        self.assertEqual(len(result.expectedFailures), 8)
        got = {case._testMethodName: detail for case, detail in result.expectedFailures}
        wanted = {
            "test_red_blank_client_owner_must_not_admit_bound_public_host",
            "test_red_blank_client_reference_must_not_admit_bound_public_network",
            "test_red_whitespace_owner_must_not_admit_bound_public_host",
            "test_red_padded_reference_must_not_admit_bound_public_network",
            "test_red_none_owner_must_not_admit_bound_public_host",
            "test_red_bool_reference_must_not_admit_bound_public_network",
            "test_red_current_legacy_grant_must_require_canonical_owner",
            "test_red_current_legacy_grant_must_require_canonical_reference",
        }
        self.assertEqual(set(got), wanted)
        for detail in got.values():
            self.assertIn("AssertionError: True is not false", detail)


if __name__ == "__main__":
    unittest.main()
