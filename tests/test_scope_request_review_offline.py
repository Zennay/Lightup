"""Real model-based offline review regressions. No network or execution."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.engagements import (
    AssessmentMode, AssessmentRequest, AuthorizationGrant, RiskLevel, ScopeDefinition
)
from lightup.scope_request_review import preview_active_request


NOW = datetime(2026, 10, 14, 5, 43, tzinfo=timezone.utc)


def sample():
    request = AssessmentRequest(
        request_id="request-01", client_id="client-a",
        requested_assets=("app.example.test",),
        requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
        requested_risk=RiskLevel.LOW_IMPACT,
        requested_by="requester-a",
    )
    grant = AuthorizationGrant(
        grant_id="grant-01", client_id="client-a",
        engagement_id="engagement-01", approved_by="operator-b",
        reference="signed-proof-UNVERIFIED",
        scope=ScopeDefinition(
            assets=("app.example.test", "api.example.test"),
            max_risk=RiskLevel.ELEVATED,
            allowed_capabilities=("http-baseline",),
            excluded_assets=("api.example.test",),
        ),
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(minutes=5),
    )
    return request, grant


class ActiveRequestReviewTests(unittest.TestCase):
    def review(self, request=None, grant=None, now=NOW):
        req, auth = sample()
        return preview_active_request(
            req if request is None else request,
            auth if grant is None else grant,
            now=now,
        )

    def test_positive_is_review_only_not_authorization(self):
        receipt = self.review()
        self.assertEqual((receipt.status, receipt.requested_asset_count),
                         ("REVIEW_ONLY", 1))
        self.assertIn("HUMAN", receipt.reason)

    def test_every_authority_flag_remains_false(self):
        request, grant = sample()
        cases = [
            preview_active_request(request, grant, now=NOW),
            preview_active_request(request, None, now=NOW),
            preview_active_request(replace(request, requested_risk=9), grant, now=NOW),
        ]
        names = {
            "authorization_verified", "permit_issued", "execution_enabled",
            "merge_approved", "release_approved",
        }
        self.assertTrue(names.issubset({f.name for f in fields(cases[0])}))
        for case in cases:
            for name in names:
                self.assertIs(getattr(case, name), False)

    def test_absent_grant_holds(self):
        req, _ = sample()
        self.assertEqual(preview_active_request(req, None, now=NOW).reason,
                         "NO_CANONICAL_GRANT")

    def test_reject_cross_tenant(self):
        req, grant = sample()
        self.assertEqual(self.review(grant=replace(grant, client_id="client-b")).reason,
                         "TENANT_MISMATCH")

    def test_no_self_approval(self):
        req, grant = sample()
        self.assertEqual(self.review(grant=replace(grant, approved_by=req.requested_by)).reason,
                         "SELF_APPROVAL")

    def test_no_wildcard_capabilities(self):
        req, grant = sample()
        self.assertEqual(
            self.review(grant=replace(grant, scope=replace(grant.scope, allowed_capabilities=()))).reason,
            "CAPABILITY_WILDCARD_OR_INVALID",
        )

    def test_no_missing_or_invalid_capability_schema(self):
        _, grant = sample()
        for capabilities in (("http-baseline", "http-baseline"), ("HTTP",), ("http-baseline", 3), ["http-baseline"]):
            with self.subTest(capabilities=capabilities):
                value = replace(grant, scope=replace(grant.scope, allowed_capabilities=capabilities))
                self.assertEqual(self.review(grant=value).status, "HOLD")

    def test_reject_asset_outside_scope_or_excluded(self):
        req, _ = sample()
        for asset in ("external.example.test", "api.example.test"):
            with self.subTest(asset=asset):
                self.assertEqual(
                    self.review(request=replace(req, requested_assets=(asset,))).reason,
                    "ASSETS_OUTSIDE_GRANT",
                )

    def test_reject_noncanonical_assets(self):
        req, _ = sample()
        for asset in ("APP.example.test", "*.example.test", "api.example.test/path",
                      "api.example.test.", " api.example.test", "аpi.example.test",
                      "127.0.0.01", 123, ""):
            with self.subTest(asset=asset):
                self.assertEqual(
                    self.review(request=replace(req, requested_assets=(asset,))).reason,
                    "INVALID_REQUEST_ASSETS",
                )

    def test_reject_duplicate_and_oversize_assets(self):
        req, _ = sample()
        for assets in ((), ("app.example.test",) * 2,
                       ("app.example.test",) * 33, ["app.example.test"]):
            with self.subTest(assets=repr(assets)[:30]):
                self.assertEqual(
                    self.review(request=replace(req, requested_assets=assets)).status, "HOLD")

    def test_explicit_ipv6_allowed_only_for_offline_review(self):
        req, grant = sample()
        asset = "2001:db8::1"
        changed = replace(grant, scope=replace(grant.scope, assets=(asset,), excluded_assets=()))
        self.assertEqual(self.review(request=replace(req, requested_assets=(asset,)),
                                     grant=changed).status, "REVIEW_ONLY")

    def test_reject_risk_escape_and_bool(self):
        req, _ = sample()
        for risk in (True, 2, RiskLevel.PASSIVE, RiskLevel.DESTRUCTIVE_LAB_ONLY):
            with self.subTest(risk=risk):
                self.assertEqual(
                    self.review(request=replace(req, requested_risk=risk)).status, "HOLD")

    def test_reject_grant_risk_escape_and_bool(self):
        _, grant = sample()
        for risk in (True, 4, RiskLevel.ANALYSIS_ONLY, RiskLevel.DESTRUCTIVE_LAB_ONLY):
            with self.subTest(risk=risk):
                self.assertEqual(self.review(
                    grant=replace(grant, scope=replace(grant.scope, max_risk=risk))
                ).status, "HOLD")

    def test_reject_risk_exceeding_grant(self):
        req, _ = sample()
        self.assertEqual(self.review(request=replace(req, requested_risk=RiskLevel.ELEVATED),
                                     grant=replace(sample()[1], scope=replace(sample()[1].scope,
                                              max_risk=RiskLevel.STANDARD))).reason,
                         "RISK_EXCEEDS_GRANT")

    def test_other_modes_hold_even_with_grant(self):
        req, _ = sample()
        for mode in (AssessmentMode.ANALYSIS_ONLY, AssessmentMode.LAB_AUTONOMOUS,
                     AssessmentMode.PASSIVE_DISCOVERY, "authorized_assessment"):
            with self.subTest(mode=mode):
                self.assertEqual(self.review(request=replace(req, requested_mode=mode)).status, "HOLD")

    def test_exact_window_end_is_expired(self):
        _, grant = sample()
        self.assertEqual(self.review(now=grant.valid_until).reason, "GRANT_NOT_CURRENT")
        self.assertEqual(self.review(now=grant.valid_from).status, "REVIEW_ONLY")

    def test_reject_naive_and_non_utc_times(self):
        _, grant = sample()
        for ts in (NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=2))), "now"):
            with self.subTest(ts=ts):
                self.assertEqual(self.review(now=ts).reason, "INVALID_TIME")
        self.assertEqual(
            self.review(grant=replace(grant, valid_from=NOW.replace(tzinfo=None))).reason,
            "INVALID_TIME",
        )

    def test_reject_inverted_window(self):
        _, grant = sample()
        changed = replace(grant, valid_from=NOW + timedelta(hours=1),
                          valid_until=NOW - timedelta(hours=1))
        self.assertEqual(self.review(grant=changed).reason, "INVALID_WINDOW")

    def test_no_credentials_or_target_reflected(self):
        req, grant = sample()
        marker = "PRIVATE_REQUEST_SECRET_87654321"
        bad = replace(req, request_id=marker, notes=marker)
        receipt = self.review(request=bad)
        self.assertNotIn(marker, str(receipt))
        self.assertEqual(receipt.requested_asset_count, 0)

    def test_reject_false_boolean_retest_marker(self):
        _, grant = sample()
        self.assertEqual(
            self.review(grant=replace(grant, recurring_retest_allowed=1)).reason,
            "INVALID_RETEST_MARKER",
        )

    def test_reject_invalid_grant_identity(self):
        _, grant = sample()
        self.assertEqual(
            self.review(grant=replace(grant, reference="\nAUTH-1")).reason,
            "INVALID_GRANT_IDENTITY",
        )

    def test_cannot_call_network_or_mutate_input(self):
        req, grant = sample()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.review(req, grant).status, "REVIEW_ONLY")
        self.assertEqual(req.requested_assets, ("app.example.test",))
        self.assertEqual(grant.scope.allowed_capabilities, ("http-baseline",))


if __name__ == "__main__":
    unittest.main()
