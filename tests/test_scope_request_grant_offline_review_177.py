"""Synthetic, I/O-free acceptance for #177. Never treats REVIEW_ONLY as authority."""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.domain import AssessmentRequestRecord, RequestStatus
from lightup.engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.request_grant_offline_review_177 import (
    ReviewStatus,
    review_request_grant,
)


NOW = datetime(2030, 2, 1, 12, tzinfo=timezone.utc)
DECIDED = datetime(2030, 1, 31, 10, tzinfo=timezone.utc)
VALID_FROM = DECIDED + timedelta(hours=1)
VALID_UNTIL = NOW + timedelta(days=2)


def request():
    return AssessmentRequestRecord(
        request_id="request-fixture",
        client_id="client-fixture",
        requested_assets=("app.example.test", "10.1.2.3", "2001:db8::1"),
        requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
        requested_risk=RiskLevel.STANDARD,
        notes="synthetic only",
        status=RequestStatus.APPROVED,
        requested_by="client-user",
        created_at="2030-01-01T00:00:00+00:00",
        decided_by="operator-fixture",
        decided_at=DECIDED.isoformat(),
    )


def grant():
    return AuthorizationGrant(
        grant_id="grant-fixture",
        client_id="client-fixture",
        engagement_id="engagement-fixture",
        approved_by="operator-fixture",
        reference="FICTIONAL-ONLY",
        scope=ScopeDefinition(
            assets=("app.example.test", "10.1.2.3"),
            max_risk=RiskLevel.LOW_IMPACT,
            allowed_capabilities=("analysis",),
            excluded_assets=(),
        ),
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        recurring_retest_allowed=False,
    )


def review(req=None, auth=None, at=NOW):
    return review_request_grant(
        request() if req is None else req,
        grant() if auth is None else auth,
        reviewed_at=at,
    )


class RequestGrantOfflineReviewTests(unittest.TestCase):
    def assert_no_authority(self, result):
        for field in (
            "authorized", "grant_allowed", "dispatch_allowed",
            "scan_allowed", "merge_allowed", "deploy_allowed",
        ):
            with self.subTest(field=field):
                self.assertIs(getattr(result, field), False)
        self.assertIn(result.reason, (
            "invalid_or_unverified_input",
            "structurally_coherent_untrusted_snapshot",
        ))
        self.assertNotIn("client-fixture", str(result))
        self.assertNotIn("app.example.test", str(result))
        self.assertNotIn("FICTIONAL-ONLY", str(result))

    def assert_hold(self, req=None, auth=None, at=NOW):
        value = review(req, auth, at)
        self.assertIs(value.status, ReviewStatus.HOLD)
        self.assert_no_authority(value)

    def test_exact_synthetic_match_is_review_only_never_approval(self):
        outcome = review()
        self.assertIs(outcome.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(outcome)
        with self.assertRaises(FrozenInstanceError):
            outcome.authorized = True

    def test_subset_narrowing_remains_review_only(self):
        narrower = replace(grant(), scope=replace(
            grant().scope, assets=("10.1.2.3",), max_risk=RiskLevel.ANALYSIS_ONLY
        ))
        result = review(auth=narrower)
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_request_status_always_requires_enum_approved(self):
        for status in (RequestStatus.SUBMITTED, RequestStatus.UNDER_REVIEW,
                       RequestStatus.REJECTED, "approved", None, True, 1):
            with self.subTest(status=status):
                self.assert_hold(req=replace(request(), status=status))

    def test_request_mode_must_be_exact_authorized_mode(self):
        for mode in (AssessmentMode.ANALYSIS_ONLY, AssessmentMode.PASSIVE_DISCOVERY,
                     AssessmentMode.LAB_AUTONOMOUS, "authorized_assessment", None):
            with self.subTest(mode=mode):
                self.assert_hold(req=replace(request(), requested_mode=mode))

    def test_wrong_client_or_wrong_approver_hold(self):
        self.assert_hold(auth=replace(grant(), client_id="other"))
        self.assert_hold(auth=replace(grant(), approved_by="other"))
        self.assert_hold(req=replace(request(), client_id="other"))
        self.assert_hold(req=replace(request(), decided_by="other"))

    def test_asset_expansion_and_duplicate_claims_hold(self):
        cases = [
            ("app.example.test", "outside.example.test"),
            ("app.example.test", "app.example.test"),
            ("app.example.test", ""),
            ("APP.EXAMPLE.TEST",),
            ("app.example.test ",),
            ("https://app.example.test",),
            ("app.example.test:443",),
            ("app.example.test.",),
            ("10.01.2.3",),
            ("2001:0db8::1",),
            ("::ffff:10.1.2.3",),
            ("10.1.2.4",),
        ]
        for assets in cases:
            with self.subTest(assets=assets):
                self.assert_hold(auth=replace(grant(), scope=replace(grant().scope, assets=assets)))

    def test_bad_request_assets_also_hold(self):
        for assets in (
            (), ["app.example.test"], ("app.example.test", "app.example.test"),
            ("App.Example.Test",), ("app.example.test/path",), ("",),
            ("10.01.2.3",), ("\N{CYRILLIC SMALL LETTER A}pp.example.test",),
        ):
            with self.subTest(assets=assets):
                self.assert_hold(req=replace(request(), requested_assets=assets))

    def test_risk_type_confusion_and_widening_hold(self):
        for risk in (RiskLevel.ELEVATED, RiskLevel.DESTRUCTIVE_LAB_ONLY,
                     3, 4, True, "3", None):
            with self.subTest(risk=risk):
                self.assert_hold(auth=replace(grant(), scope=replace(grant().scope, max_risk=risk)))
        for risk in (3, True, "3", None, RiskLevel.DESTRUCTIVE_LAB_ONLY):
            with self.subTest(request_risk=risk):
                self.assert_hold(req=replace(request(), requested_risk=risk))

    def test_untrusted_metadata_cannot_smuggle_invalid_scopes(self):
        for excluded in (
            ["app.example.test"], ("a", "a"), (" BAD",),
            ("https://example.test",), (None,),
        ):
            with self.subTest(excluded=excluded):
                self.assert_hold(auth=replace(grant(), scope=replace(
                    grant().scope, excluded_assets=excluded
                )))
        for allowed in (
            ["analysis"], ("analysis", "analysis"), ("",), (1,), (" bad",),
        ):
            with self.subTest(capabilities=allowed):
                self.assert_hold(auth=replace(grant(), scope=replace(
                    grant().scope, allowed_capabilities=allowed
                )))
        self.assert_hold(auth=replace(grant(), recurring_retest_allowed=1))

    def test_decision_datetime_must_be_canonical_utc(self):
        for stamp in (
            None, "", "tomorrow", "2030-01-31T10:00:00Z",
            "2030-01-31T10:00:00+01:00",
            "2030-01-31T24:00:00+00:00",
            "2030-01-31T10:60:00+00:00",
            "2030-02-30T10:00:00+00:00",
            "2030-01-31t10:00:00+00:00",
            "2030-01-31T10:00:00+00:00 extra",
            0, False,
        ):
            with self.subTest(stamp=stamp):
                self.assert_hold(req=replace(request(), decided_at=stamp))
        self.assert_hold(req=replace(request(), decided_at=(
            NOW + timedelta(seconds=1)).isoformat()))

    def test_validity_window_boundaries_and_time_type(self):
        for changes in (
            {"valid_from": NOW + timedelta(seconds=1)},
            {"valid_until": NOW - timedelta(seconds=1)},
            {"valid_from": DECIDED - timedelta(seconds=1)},
            {"valid_from": None},
            {"valid_until": False},
            {"valid_from": "2030-01-31"},
            {"valid_until": datetime(2030, 2, 2)},
        ):
            with self.subTest(changes=changes):
                self.assert_hold(auth=replace(grant(), **changes))
        for instant in (None, 0, False, "2030-02-01", datetime(2030, 2, 1)):
            with self.subTest(instant=instant):
                self.assert_hold(at=instant)

    def test_window_is_inclusive_only_in_non_authorizing_review(self):
        for at in (VALID_FROM, VALID_UNTIL):
            with self.subTest(at=at):
                result = review(at=at)
                self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
                self.assert_no_authority(result)

    def test_reject_subclasses_at_object_admission(self):
        class Imposter(str):
            pass

        class RequestSubclass(AssessmentRequestRecord):
            pass

        class GrantSubclass(AuthorizationGrant):
            pass

        self.assertIs(
            review_request_grant(RequestSubclass(**request().__dict__), grant(), reviewed_at=NOW).status,
            ReviewStatus.HOLD,
        )
        self.assertIs(
            review_request_grant(request(), GrantSubclass(**grant().__dict__), reviewed_at=NOW).status,
            ReviewStatus.HOLD,
        )
        self.assert_hold(req=replace(request(), request_id=Imposter("request-fixture")))
        self.assert_hold(auth=replace(grant(), reference=Imposter("FICTIONAL-ONLY")))

    def test_no_network_or_clock_dependency_for_synthetic_input(self):
        from unittest.mock import patch
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            result = review()
            self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
            self.assert_no_authority(result)

    def test_no_raw_input_echo_on_denial(self):
        poisoned = replace(request(), requested_assets=("secret-password.example.test",))
        result = review(req=poisoned)
        self.assert_no_authority(result)
        self.assertNotIn("secret-password", str(result))


if __name__ == "__main__":
    unittest.main()
