"""Real contract tests for opt-in grant revision review (no real targets)."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import IntEnum
import unittest
from unittest.mock import patch

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_revision_review import review_grant_revision


START = datetime(2026, 10, 1, tzinfo=timezone.utc)
END = datetime(2026, 10, 2, tzinfo=timezone.utc)


def grant(**overrides):
    options = {
        "grant_id": "g1",
        "client_id": "client1",
        "engagement_id": "eng1",
        "approved_by": "operator1",
        "reference": "ref1",
        "scope": ScopeDefinition(
            assets=("a.example.test", "b.example.test"),
            excluded_assets=("b.example.test",),
            allowed_capabilities=("headers", "tls"),
            max_risk=RiskLevel.STANDARD,
        ),
        "valid_from": START,
        "valid_until": END,
        "recurring_retest_allowed": True,
    }
    options.update(overrides)
    return AuthorizationGrant(**options)


def proposal(**scope_updates):
    return grant(scope=replace(grant().scope, **scope_updates))


class GrantRevisionReviewTests(unittest.TestCase):
    def assert_hold(self, old, new, reason=None):
        receipt = review_grant_revision(old, new)
        self.assertEqual(receipt.verdict, "HOLD")
        if reason is not None:
            self.assertEqual(receipt.reason_code, reason)
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.permit_issued)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.merge_approved)
        self.assertFalse(receipt.release_approved)
        return receipt

    def test_exact_same_grant_is_review_not_permission(self):
        receipt = review_grant_revision(grant(), grant())
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertEqual(receipt.narrowed_fields, ())
        self.assertFalse(receipt.authorization_verified)
        self.assertFalse(receipt.permit_issued)
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.merge_approved)
        self.assertFalse(receipt.release_approved)

    def test_atomic_multiple_narrowings(self):
        old = grant()
        new = replace(
            proposal(assets=("a.example.test",), excluded_assets=(),
                     allowed_capabilities=("headers",), max_risk=RiskLevel.LOW_IMPACT),
            valid_from=START + timedelta(hours=1),
            valid_until=END - timedelta(hours=1),
            recurring_retest_allowed=False,
        )
        receipt = review_grant_revision(old, new)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertEqual(receipt.narrowed_fields, (
            "assets", "excluded_assets", "capabilities", "risk",
            "window", "recurring_retest",
        ))

    def test_identity_changes_are_denied(self):
        for field in ("grant_id", "client_id", "engagement_id", "approved_by", "reference"):
            with self.subTest(field=field):
                self.assert_hold(grant(), replace(grant(), **{field: "different"}), "identity_changed")

    def test_identity_spoofing_types_are_denied(self):
        class FakeStr(str):
            pass
        for identity in (None, True, 4, FakeStr("ref1"), " ref1", "", "é", "bad\nvalue"):
            with self.subTest(identity=repr(identity)):
                self.assert_hold(grant(), replace(grant(), reference=identity), "invalid_identity")

    def test_asset_addition_is_denied(self):
        self.assert_hold(grant(), proposal(assets=("a.example.test", "b.example.test", "c.example.test")), "asset_expansion")

    def test_exclusion_removal_is_denied(self):
        self.assert_hold(grant(), proposal(excluded_assets=()), "exclusion_removed")

    def test_explicit_capabilities_cannot_become_wildcard(self):
        self.assert_hold(grant(), proposal(allowed_capabilities=()), "capability_expansion")

    def test_extra_capability_is_denied(self):
        self.assert_hold(grant(), proposal(allowed_capabilities=("headers", "tls", "ssh")), "capability_expansion")

    def test_capability_wildcard_in_old_grant_can_narrow(self):
        old = proposal(allowed_capabilities=())
        new = proposal(allowed_capabilities=("headers",))
        self.assertEqual(review_grant_revision(old, new).verdict, "REVIEW_ONLY")

    def test_proposed_unrestricted_capabilities_is_held_even_from_wildcard(self):
        old = proposal(allowed_capabilities=())
        self.assert_hold(old, old, "unrestricted_proposed_capabilities")

    def test_risk_escalation_is_denied(self):
        self.assert_hold(proposal(max_risk=RiskLevel.LOW_IMPACT), grant(), "risk_expansion")

    def test_destructive_risk_is_denied_even_if_unchanged(self):
        dangerous = proposal(max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)
        self.assert_hold(dangerous, dangerous, "destructive_risk_not_reviewable")

    def test_risk_must_be_exact_enum_not_int_or_foreign_intenum(self):
        class ForeignRisk(IntEnum):
            STANDARD = 3
        for risk in (3, True, ForeignRisk.STANDARD, "3"):
            with self.subTest(risk=risk):
                self.assert_hold(grant(), proposal(max_risk=risk), "invalid_scope")

    def test_window_extension_both_ends_denied(self):
        old = grant()
        for proposed in (
            replace(old, valid_from=START - timedelta(seconds=1)),
            replace(old, valid_until=END + timedelta(seconds=1)),
        ):
            with self.subTest(proposed=proposed.valid_from):
                self.assert_hold(old, proposed, "window_expansion")

    def test_expired_grant_review_never_authorizes(self):
        old = grant(valid_from=START - timedelta(days=30), valid_until=START - timedelta(days=29))
        receipt = review_grant_revision(old, old)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertFalse(receipt.execution_enabled)

    def test_naive_window_denied(self):
        self.assert_hold(grant(), grant(valid_until=END.replace(tzinfo=None)), "invalid_utc_window")

    def test_non_utc_window_denied(self):
        shifted = END.astimezone(timezone(timedelta(hours=2)))
        self.assert_hold(grant(), grant(valid_until=shifted), "invalid_utc_window")

    def test_reversed_windows_denied(self):
        self.assert_hold(grant(), grant(valid_from=END + timedelta(seconds=1)), "invalid_window_order")

    def test_boolean_retest_forgery_denied(self):
        self.assert_hold(grant(), grant(recurring_retest_allowed=1), "invalid_retest_authority")

    def test_retest_widening_denied(self):
        old = grant(recurring_retest_allowed=False)
        self.assert_hold(old, grant(recurring_retest_allowed=True), "retest_authority_expansion")

    def test_type_confused_grant_denied(self):
        class FakeGrant(AuthorizationGrant):
            pass
        self.assert_hold(grant(), None, "invalid_grant_type")
        self.assert_hold(grant(), FakeGrant(**vars(grant())), "invalid_grant_type")

    def test_scope_subclass_denied(self):
        class FakeScope(ScopeDefinition):
            pass
        self.assert_hold(grant(), grant(scope=FakeScope(**vars(grant().scope))), "invalid_scope")

    def test_canonical_ip_literals_and_networks_are_reviewable_only(self):
        scope = replace(
            grant().scope,
            assets=("127.0.0.1", "2001:db8::1", "192.168.0.0/24"),
            excluded_assets=(),
        )
        synthetic = grant(scope=scope)
        receipt = review_grant_revision(synthetic, synthetic)
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")
        self.assertFalse(receipt.execution_enabled)
        self.assertFalse(receipt.authorization_verified)

    def test_numeric_host_aliases_and_noncanonical_cidr_fail_closed(self):
        for alias in (
            "127.1", "2130706433", "0x7f000001", "0x7f.0.0.1",
            "192.168.01.1", "2001:0db8::1",
            "192.168.0.1/24", "192.168.0.0/024",
        ):
            with self.subTest(alias=alias):
                candidate = proposal(
                    assets=("a.example.test", alias),
                    excluded_assets=(),
                )
                self.assert_hold(grant(), candidate, "invalid_scope")

    def test_host_aliases_unicode_and_duplicate_targets_denied(self):
        for assets in (
            ("A.example.test", "b.example.test"),
            ("a.example.test.", "b.example.test"),
            ("a.example.test", "a.example.test"),
            ("a.example.test", "é.example.test"),
            ("a.example.test", "b..example.test"),
        ):
            with self.subTest(assets=assets):
                self.assert_hold(grant(), proposal(assets=assets), "invalid_scope")

    def test_hidden_exclusion_or_wrong_tuple_shapes_denied(self):
        for assets in (["a.example.test"], (), tuple(["a.example.test"] * 129)):
            with self.subTest(assets=assets):
                self.assert_hold(grant(), proposal(assets=assets), "invalid_scope")
        self.assert_hold(grant(), proposal(excluded_assets=("not-registered.example.test",)), "invalid_scope")

    def test_no_socket_or_database_interactions(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("sqlite3.connect", side_effect=AssertionError("database forbidden")):
            receipt = review_grant_revision(grant(), grant())
        self.assertEqual(receipt.verdict, "REVIEW_ONLY")

    def test_denial_receipts_do_not_reflect_private_asset_or_identity(self):
        secret = "secret-tenant-a.example.test"
        denied = review_grant_revision(grant(), proposal(assets=(secret,)))
        self.assertEqual(denied.verdict, "HOLD")
        self.assertNotIn(secret, repr(denied))
        self.assertNotIn("client1", repr(denied))


if __name__ == "__main__":
    unittest.main()
