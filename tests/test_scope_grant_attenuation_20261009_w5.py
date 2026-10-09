"""Offline real-domain regressions for deny-only grant scope reductions."""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.grant_attenuation import compare_grant_attenuation


START = datetime(2026, 10, 9, 10, tzinfo=timezone.utc)
END = START + timedelta(days=2)


def approved() -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="grant-1",
        client_id="tenant-1",
        engagement_id="engagement-1",
        approved_by="operator-1",
        reference="signed-approval-1",
        scope=ScopeDefinition(
            assets=("app.example.test", "api.example.test"),
            max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("headers", "tls", "port_inventory"),
            excluded_assets=("api.example.test",),
        ),
        valid_from=START,
        valid_until=END,
        recurring_retest_allowed=False,
    )


class GrantAttenuationTests(unittest.TestCase):
    def assert_rejected(self, value, reason: str) -> None:
        decision = compare_grant_attenuation(approved(), value)
        self.assertFalse(decision.nonexpanding)
        self.assertIn(reason, decision.reasons)
        self.assertFalse(decision.grants_execution_authority)

    def test_exact_snapshot_is_nonexpanding_but_not_authorizing(self):
        decision = compare_grant_attenuation(approved(), approved())
        self.assertTrue(decision.nonexpanding)
        self.assertEqual((), decision.reasons)
        self.assertFalse(decision.grants_execution_authority)

    def test_valid_narrowed_asset_capability_risk_and_window(self):
        old = approved()
        proposed = replace(
            old,
            scope=replace(
                old.scope,
                assets=("app.example.test",),
                allowed_capabilities=("headers",),
                excluded_assets=("api.example.test", "app.example.test"),
                max_risk=RiskLevel.PASSIVE,
            ),
            valid_from=START + timedelta(hours=1),
            valid_until=END - timedelta(hours=1),
        )
        self.assertTrue(compare_grant_attenuation(old, proposed).nonexpanding)

    def test_additional_asset_denied(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, assets=old.scope.assets + ("new.example.test",))),
            "assets_expanded",
        )

    def test_removed_exclusion_denied(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, excluded_assets=())),
            "exclusions_removed",
        )

    def test_risk_increase_denied(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, max_risk=RiskLevel.ELEVATED)),
            "risk_expanded",
        )

    def test_new_capability_denied(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, allowed_capabilities=("headers", "ssh"))),
            "capabilities_expanded",
        )

    def test_empty_capability_list_is_unrestricted_not_empty(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, allowed_capabilities=())),
            "capabilities_expanded",
        )

    def test_unrestricted_baseline_can_be_narrowed(self):
        old = approved()
        old = replace(old, scope=replace(old.scope, allowed_capabilities=()))
        proposed = replace(old, scope=replace(old.scope, allowed_capabilities=("headers",)))
        self.assertTrue(compare_grant_attenuation(old, proposed).nonexpanding)

    def test_earlier_start_denied(self):
        old = approved()
        self.assert_rejected(replace(old, valid_from=START - timedelta(seconds=1)), "window_start_expanded")

    def test_later_expiry_denied(self):
        old = approved()
        self.assert_rejected(replace(old, valid_until=END + timedelta(seconds=1)), "window_end_expanded")

    def test_retest_privilege_increase_denied(self):
        old = approved()
        self.assert_rejected(replace(old, recurring_retest_allowed=True), "retest_privilege_expanded")

    def test_identity_binding_all_fields(self):
        old = approved()
        for field in ("grant_id", "client_id", "engagement_id", "approved_by", "reference"):
            with self.subTest(field=field):
                self.assert_rejected(replace(old, **{field: "different"}), "identity_changed:" + field)

    def test_rejects_polymorphic_authorization_grants(self):
        class SubGrant(AuthorizationGrant):
            pass
        old = approved()
        for p, q in ((SubGrant(**old.__dict__), old), (old, SubGrant(**old.__dict__)), (None, old)):
            with self.subTest(kind=type(p).__name__):
                self.assertEqual(("invalid_grant_type",), compare_grant_attenuation(p, q).reasons)

    def test_rejects_integer_risk_even_if_numeric_value_matches(self):
        old = approved()
        self.assert_rejected(replace(old, scope=replace(old.scope, max_risk=3)), "invalid_scope_shape")

    def test_rejects_list_subclass_and_duplicate_scope_identity(self):
        old = approved()
        for values in (
            ["app.example.test"],
            ("app.example.test", "APP.EXAMPLE.TEST"),
            ("app.example.test", " app.example.test"),
            ("app.example.test", "\nunsafe"),
        ):
            with self.subTest(values=values):
                self.assert_rejected(replace(old, scope=replace(old.scope, assets=values)), "invalid_scope_shape")

    def test_rejects_duplicate_capability(self):
        old = approved()
        self.assert_rejected(
            replace(old, scope=replace(old.scope, allowed_capabilities=("tls", "tls"))),
            "invalid_scope_shape",
        )

    def test_rejects_nonbool_retest_flags(self):
        old = approved()
        self.assert_rejected(replace(old, recurring_retest_allowed=1), "invalid_retest_flag")

    def test_rejects_naive_and_inverted_windows(self):
        old = approved()
        self.assert_rejected(replace(old, valid_from=START.replace(tzinfo=None)), "invalid_time_window")
        self.assert_rejected(replace(old, valid_until=START), "invalid_time_window")

    def test_same_instant_with_different_timezone_is_not_expansion(self):
        old = approved()
        plus2 = timezone(timedelta(hours=2))
        changed = replace(
            old,
            valid_from=START.astimezone(plus2),
            valid_until=END.astimezone(plus2),
        )
        self.assertTrue(compare_grant_attenuation(old, changed).nonexpanding)

    def test_never_modifies_grants(self):
        old = approved()
        newer = replace(old, scope=replace(old.scope, assets=("app.example.test",)))
        before = repr((old, newer))
        compare_grant_attenuation(old, newer)
        self.assertEqual(before, repr((old, newer)))


if __name__ == "__main__":
    unittest.main()
