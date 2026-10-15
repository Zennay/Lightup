"""#291 on actual PR #100 source: synthetic asset-bound IPv6 identity acceptance.

PARENT IS THE EXACT UNMERGED PR #100 COMMIT, NOT MAIN. All exercises are
in-memory and use RFC3849 documentation IPv6; no customer grants or network.
Expected RED means a real source defect, not a successful authorization test.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import sys
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason

ALIAS = "2001"
LITERAL = "2001:db8:55::beef"
CAPABILITY = "fixture-no-adapter"


def _authorization(*, asset=ALIAS, revoked=False, expired=False):
    return Authorization(
        owner="fixture-owner-not-a-customer",
        reference="NO-REAL-CONSENT",
        assets=(asset,) if asset is not None else (),
        revoked_at=datetime(2026, 1, 1, tzinfo=timezone.utc) if revoked else None,
        revoked_by="synthetic-fixture" if revoked else None,
        revocation_reason="offline-test-only" if revoked else None,
        valid_until=datetime(2020, 1, 1, tzinfo=timezone.utc) if expired else None,
    )


def _scope(*, alias=True, cidr=False):
    return ScopePolicy(
        allow_private_lab=False,
        explicit_hosts=frozenset((ALIAS,)) if alias else frozenset(),
        explicit_networks=(LITERAL + "/128",) if cidr else (),
        require_authorization_for_public=True,
    )


def _gate(scope):
    return ActivationGate(
        scope,
        ActivationPolicy(
            mode=ActivationMode.AUTHORIZED,
            activation_reference="NOT-A-LIVE-ACTIVATION",
        ),
    )


class SourceOwnerAssetIPv6Boundary(unittest.TestCase):
    """No modifies to source owner or execution pathways."""

    def no_network(self):
        guards = ExitStack()
        guards.enter_context(patch.object(
            socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")
        ))
        guards.enter_context(patch.object(
            socket, "socket", side_effect=AssertionError("network socket forbidden")
        ))
        guards.enter_context(patch.object(
            socket, "create_connection", side_effect=AssertionError("network connect forbidden")
        ))
        return guards

    @unittest.expectedFailure
    def test_red_owner_asset_alias_cannot_admit_bare_ipv6(self):
        with self.no_network():
            decision = _scope().decide(Target(LITERAL, authorization=_authorization()))
        self.assertFalse(decision.allowed, decision)

    @unittest.expectedFailure
    def test_red_owner_alias_cannot_mint_wrong_identity_permit(self):
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            return_value="FAKE-NEVER-AUTHORIZED",
        ), self.assertRaises(PermissionError):
            _gate(_scope()).issue(
                Target(LITERAL, authorization=_authorization()), CAPABILITY
            )

    @unittest.expectedFailure
    def test_red_128_distinct_wrong_ipv6_assets_all_denied(self):
        wrongly_admitted = []
        with self.no_network():
            for offset in range(128):
                address = str(ipaddress.IPv6Address(f"2001:db8:55::{offset + 1:x}"))
                result = _scope().decide(
                    Target(address, authorization=_authorization())
                )
                if result.allowed:
                    wrongly_admitted.append(address)
        self.assertEqual(
            wrongly_admitted, [],
            f"{len(wrongly_admitted)} owner-source wrong-asset admissions",
        )

    def test_exact_ipv6_asset_does_not_match_unrelated_alias(self):
        with self.no_network():
            result = _scope().decide(
                Target(LITERAL, authorization=_authorization(asset=LITERAL))
            )
        self.assertFalse(result.allowed)
        self.assertEqual(result.normalized_host, ALIAS)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_ASSET_MISMATCH)

    def test_empty_asset_cannot_create_scope_membership(self):
        with self.no_network():
            result = _scope().decide(
                Target(LITERAL, authorization=_authorization(asset=None))
            )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, ScopeReason.AUTHORIZATION_ASSET_MISMATCH)

    def test_bracketed_exact_ipv6_cidr_asset_retains_whole_identity(self):
        target = Target("[" + LITERAL + "]", authorization=_authorization(asset=LITERAL))
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            return_value="FAKE-NEVER-AUTHORIZED",
        ):
            result = _scope(alias=False, cidr=True).decide(target)
            permit = _gate(_scope(alias=False, cidr=True)).issue(target, CAPABILITY)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, ScopeReason.EXPLICIT_NETWORK)
        self.assertEqual(result.normalized_host, LITERAL)
        self.assertEqual(permit.target, LITERAL)
        self.assertEqual(permit.authorization_reference, "NO-REAL-CONSENT")
        self.assertEqual(permit.permit_id, "FAKE-NEVER-AUTHORIZED")

    def test_bracketed_cidr_wrong_asset_does_not_mint_token(self):
        target = Target("[" + LITERAL + "]", authorization=_authorization(asset=ALIAS))
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            side_effect=AssertionError("token issuance forbidden"),
        ), self.assertRaises(PermissionError):
            _gate(_scope(alias=False, cidr=True)).issue(target, CAPABILITY)

    def test_revoked_claim_denied_before_token_issuance(self):
        target = Target(LITERAL, authorization=_authorization(revoked=True))
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            side_effect=AssertionError("token issuance forbidden"),
        ), self.assertRaises(PermissionError):
            _gate(_scope()).issue(target, CAPABILITY)
        self.assertEqual(
            _scope().decide(target).reason, ScopeReason.AUTHORIZATION_REVOKED
        )

    def test_expired_claim_denied_before_token_issuance(self):
        target = Target(LITERAL, authorization=_authorization(expired=True))
        with self.no_network(), patch(
            "lightup.activation.token_urlsafe",
            side_effect=AssertionError("token issuance forbidden"),
        ), self.assertRaises(PermissionError):
            _gate(_scope()).issue(target, CAPABILITY)
        self.assertEqual(
            _scope().decide(target).reason, ScopeReason.AUTHORIZATION_EXPIRED
        )

    def test_tripwire_blocks_software_network_calls(self):
        with self.no_network():
            with self.assertRaisesRegex(AssertionError, "DNS forbidden"):
                socket.getaddrinfo("no-real-target.example.test", 443)
            with self.assertRaisesRegex(AssertionError, "network socket forbidden"):
                socket.socket()

    def test_owner_source_reds_are_real_assertions_not_masked_exceptions(self):
        expected_messages = {
            "test_red_owner_asset_alias_cannot_admit_bare_ipv6": "True is not false",
            "test_red_owner_alias_cannot_mint_wrong_identity_permit": "PermissionError not raised",
            "test_red_128_distinct_wrong_ipv6_assets_all_denied": "128 owner-source wrong-asset admissions",
        }
        for method, message in expected_messages.items():
            with self.subTest(method=method):
                result = unittest.TestResult()
                SourceOwnerAssetIPv6Boundary(method).run(result)
                self.assertEqual(result.errors, [])
                self.assertEqual(result.failures, [])
                self.assertEqual(result.unexpectedSuccesses, [])
                self.assertEqual(len(result.expectedFailures), 1)
                trace = result.expectedFailures[0][1]
                self.assertIn("AssertionError:", trace)
                self.assertIn(message, trace)
                for forbidden in (
                    "TypeError:", "AttributeError:", "ValueError:",
                    "DNS forbidden", "network socket forbidden",
                    "network connect forbidden",
                ):
                    self.assertNotIn(forbidden, trace)


if __name__ == "__main__":
    unittest.main()
