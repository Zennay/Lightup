"""Independent offline ActivationGate/StrictTargetScopePolicy permit-order proof (#1289).

This is a stacked, add-only acceptance suite on the frozen head of draft #1290.
No target connection, DNS lookup, grant write, scanner, deploy, or external model.
"""
from __future__ import annotations

import socket
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.strict_target_scope_optin import StrictTargetScopePolicy


def _offline_authorization(*, expired: bool = False) -> Authorization:
    until = datetime.now(timezone.utc) + timedelta(days=-1 if expired else 1)
    return Authorization("synthetic-asset-owner", "SYNTHETIC-ONLY", valid_until=until)


class IndependentPermitBoundary1289Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = StrictTargetScopePolicy(ScopePolicy())
        self.public = StrictTargetScopePolicy(ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"app.example.test"}),
            explicit_networks=("8.8.8.0/24",),
        ))

    @staticmethod
    def gate(policy: StrictTargetScopePolicy, mode: ActivationMode):
        return ActivationGate(
            policy, ActivationPolicy(mode=mode, activation_reference="SYNTHETIC-LAB-ONLY")
        )

    def assert_refused_without_token(
        self, policy: StrictTargetScopePolicy, mode: ActivationMode, target: Target
    ) -> None:
        # Token creation is the last in-process permit-issuance boundary.
        with patch("lightup.activation.token_urlsafe") as mint:
            with self.assertRaises(PermissionError):
                self.gate(policy, mode).issue(target, "inert-no-adapter")
            mint.assert_not_called()

    def test_malformed_lab_target_never_mints_execution_permit(self):
        for raw in (
            "http://lo\\ncalhost",
            "http://operator@localhost",
            "http://localhost:0",
            "http://localhost:65536",
            "http://[::1]:bogus",
            "http://[::1]suffix",
            "http://localhost%2e",
            "//localhost",
            "localhost/hidden",
            "https://localhost\\@external.invalid",
        ):
            # Turn escaped CR/LF into a real newline for the parser differential.
            raw = raw.replace("\\n", "\n")
            with self.subTest(raw=repr(raw)):
                self.assert_refused_without_token(
                    self.private, ActivationMode.LAB_ONLY, Target(raw)
                )
                decision = self.private.decide(Target(raw))
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_malformed_authorized_target_denied_even_with_current_auth(self):
        authority = _offline_authorization()
        for raw in (
            "https://operator@app.example.test",
            "https://app.example.test:65536/",
            "https://app.example.test:word/",
            "https://app.example.test%2e/",
            "https://app.example.test#fragment",
            "https://app.example.test\\@external.invalid/",
        ):
            with self.subTest(raw=raw):
                self.assert_refused_without_token(
                    self.public, ActivationMode.AUTHORIZED,
                    Target(raw, authorization=authority),
                )

    def test_invalid_lexical_identity_never_calls_legacy_scope_or_auth(self):
        authorization = _offline_authorization()
        with patch.object(ScopePolicy, "decide", side_effect=AssertionError("legacy called")) as legacy:
            with patch.object(Authorization, "is_current", side_effect=AssertionError("auth read")) as auth_check:
                result = self.public.decide(
                    Target("https://user@app.example.test", authorization=authorization)
                )
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)
                legacy.assert_not_called()
                auth_check.assert_not_called()

    def test_invalid_target_subclass_is_rejected_before_permit(self):
        class TargetSubclass(Target):
            pass

        self.assert_refused_without_token(
            self.private, ActivationMode.LAB_ONLY, TargetSubclass("localhost")
        )
        result = self.private.decide(TargetSubclass("localhost"))
        self.assertEqual(result.reason, ScopeReason.INVALID_TARGET)

    def test_valid_local_target_yields_only_canonical_host_not_url(self):
        with patch("lightup.activation.token_urlsafe", return_value="OFFLINE-PERMIT") as mint:
            permit = self.gate(self.private, ActivationMode.LAB_ONLY).issue(
                Target("http://LOCALHOST.:8800/synthetic/path?key=synthetic"),
                "inert-no-adapter",
            )
        mint.assert_called_once_with(24)
        self.assertEqual(permit.permit_id, "OFFLINE-PERMIT")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)
        self.assertEqual(permit.target, "localhost")
        self.assertEqual(permit.capability_id, "inert-no-adapter")
        self.assertNotIn("?", permit.target)
        self.assertNotIn("/", permit.target)

    def test_bracketed_ipv6_lab_permit_matches_original_canonical_identity(self):
        with patch("lightup.activation.token_urlsafe", return_value="OFFLINE-IPV6"):
            permit = self.gate(self.private, ActivationMode.LAB_ONLY).issue(
                Target("https://[0:0:0:0:0:0:0:1]:443/local"), "inert-no-adapter"
            )
        self.assertEqual(permit.target, "::1")
        self.assertEqual(permit.mode, ActivationMode.LAB_ONLY)

    def test_current_explicit_public_host_stays_authorized_only_when_enabled(self):
        target = Target(
            "https://APP.EXAMPLE.TEST:443/a?b=1",
            authorization=_offline_authorization(),
        )
        self.assert_refused_without_token(self.public, ActivationMode.LAB_ONLY, target)
        with patch("lightup.activation.token_urlsafe", return_value="OFFLINE-PUBLIC"):
            permit = self.gate(self.public, ActivationMode.AUTHORIZED).issue(
                target, "inert-no-adapter"
            )
        self.assertEqual(permit.target, "app.example.test")
        self.assertEqual(permit.mode, ActivationMode.AUTHORIZED)
        self.assertEqual(permit.activation_reference, "SYNTHETIC-LAB-ONLY")

    def test_public_host_requires_current_grant_before_permit(self):
        for authorization in (None, _offline_authorization(expired=True)):
            with self.subTest(authorization=authorization):
                self.assert_refused_without_token(
                    self.public, ActivationMode.AUTHORIZED,
                    Target("app.example.test", authorization=authorization),
                )

    def test_unlisted_public_asset_not_granted_by_approval_for_other_asset(self):
        self.assert_refused_without_token(
            self.public, ActivationMode.AUTHORIZED,
            Target("unlisted.example.test", authorization=_offline_authorization()),
        )

    def test_plan_only_valid_host_never_creates_permit(self):
        self.assert_refused_without_token(
            self.private, ActivationMode.PLAN_ONLY, Target("http://localhost")
        )

    def test_decisions_do_not_require_network_or_dns(self):
        with (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")) as dns,
            patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")) as connect,
        ):
            permitted = self.private.decide(Target("https://localhost:443/"))
            refused = self.public.decide(
                Target("https://unlisted.example.test", authorization=_offline_authorization())
            )
            self.assertTrue(permitted.allowed)
            self.assertFalse(refused.allowed)
            dns.assert_not_called()
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
