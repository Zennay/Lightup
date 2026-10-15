"""Synthetic, I/O-free acceptance for #177. Never treats REVIEW_ONLY as authority."""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.capabilities import CapabilityState, get_capabilities
from lightup.domain import AssessmentRequestRecord, EngagementRecord, RequestStatus
from lightup.engagements import AssessmentMode, AuthorizationGrant, EngagementStatus, RiskLevel, ScopeDefinition
from lightup.request_grant_offline_review_177 import (
    ReviewStatus,
    RequestGrantReview,
    review_request_grant,
    review_request_grant_batch,
    review_request_grant_engagement,
    review_request_grant_engagement_batch,
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
            allowed_capabilities=("web-baseline",),
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
            ["web-baseline"], ("web-baseline", "web-baseline"), ("",), (1,), (" bad",),
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

    def test_invalid_request_creation_cannot_be_rewritten_as_approval(self):
        for stamp in (
            None, "", 0, False, "2030-02-30T00:00:00+00:00",
            "2030-01-01T24:00:00+00:00",
            "2030-01-01T00:00:00Z",
            (DECIDED + timedelta(seconds=1)).isoformat(),
            (NOW + timedelta(days=1)).isoformat(),
        ):
            with self.subTest(created_at=stamp):
                self.assert_hold(req=replace(request(), created_at=stamp))

    def test_capability_wildcard_never_becomes_structurally_reviewable(self):
        self.assert_hold(auth=replace(grant(), scope=replace(
            grant().scope, allowed_capabilities=()
        )))
        self.assert_hold(auth=replace(grant(), scope=replace(
            grant().scope, allowed_capabilities=("web-baseline", "web-baseline")
        )))

    def test_exclusions_must_belong_to_granted_asset_set(self):
        self.assert_hold(auth=replace(grant(), scope=replace(
            grant().scope, excluded_assets=("unknown.example.test",)
        )))
        narrowed = replace(grant(), scope=replace(
            grant().scope, excluded_assets=("10.1.2.3",)
        ))
        result = review(auth=narrowed)
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_identifier_controls_and_boundaries(self):
        for bad in (
            "bad name", "bad\\nname", "bad/name", "-bad",
            "_bad", "bad\\tname", "bad!name", "x" * 129,
        ):
            with self.subTest(bad=bad):
                self.assert_hold(auth=replace(grant(), approved_by=bad))
        self.assert_hold(req=replace(request(), request_id="x" * 129))
        self.assert_hold(auth=replace(grant(), reference="secret\\nnewline"))
        self.assert_hold(auth=replace(grant(), engagement_id=""))

    def test_untrusted_timezone_classes_are_denied_without_callback(self):
        from datetime import tzinfo

        class PoisonTimezone(tzinfo):
            def utcoffset(self, value):
                raise AssertionError("untrusted timezone callback must not execute")

            def dst(self, value):
                raise AssertionError("unexpected DST callback")

            def tzname(self, value):
                raise AssertionError("unexpected zone callback")

        poisoned = VALID_FROM.replace(tzinfo=PoisonTimezone())
        self.assert_hold(auth=replace(grant(), valid_from=poisoned))
        self.assert_hold(at=poisoned)

    def test_grant_and_review_time_require_exact_builtin_utc(self):
        nonutc = timezone(timedelta(hours=1))
        for value in (
            VALID_FROM.replace(tzinfo=nonutc),
            VALID_FROM.replace(tzinfo=timezone(timedelta(hours=-5))),
            datetime(2030, 1, 31, 11),
        ):
            with self.subTest(value=value):
                self.assert_hold(auth=replace(grant(), valid_from=value))
                self.assert_hold(auth=replace(grant(), valid_until=value))
                self.assert_hold(at=value)

    def test_capability_catalog_rejects_unknown_and_lab_only(self):
        capabilities = get_capabilities()
        self.assertTrue(any(cap.state is CapabilityState.LAB_ONLY for cap in capabilities))
        self.assertTrue(any(cap.state is CapabilityState.PLANNING for cap in capabilities))
        for capability in capabilities:
            with self.subTest(capability=capability.capability_id):
                candidate = replace(grant(), scope=replace(
                    grant().scope, allowed_capabilities=(capability.capability_id,)
                ))
                result = review(auth=candidate)
                if capability.state is CapabilityState.PLANNING:
                    self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
                else:
                    self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)
        for item in (
            "analysis", "web-baselinE", "LAB_ACTIVE",
            "unknown-capability", "web-baseline ", "", 17, True,
        ):
            with self.subTest(invalid_id=item):
                self.assert_hold(auth=replace(grant(), scope=replace(
                    grant().scope, allowed_capabilities=(item,)
                )))

    @staticmethod
    def _batch_pairs():
        req1 = request()
        req2 = replace(request(), request_id="request-second")
        grant1 = replace(grant(), scope=replace(
            grant().scope, assets=("app.example.test",)
        ))
        grant2 = replace(grant(), grant_id="grant-second", scope=replace(
            grant().scope, assets=("10.1.2.3",)
        ))
        return ((req1, grant1), (req2, grant2))

    def test_atomic_batch_two_valid_is_still_non_authorizing(self):
        result = review_request_grant_batch(self._batch_pairs(), reviewed_at=NOW)
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_atomic_batch_rejects_unsupported_shapes_and_bounds(self):
        base = self._batch_pairs()
        for packet in (
            None, [], (), list(base), (list(base[0]),),
            ("fake",), ((base[0][0],),), ((base[0][0], base[0][1], 42),),
            base * 17, (base[0], base[1], None),
        ):
            with self.subTest(kind=str(type(packet)), size=len(packet) if hasattr(packet, "__len__") else -1):
                result = review_request_grant_batch(packet, reviewed_at=NOW)
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)
        for i in range(33):
            packet = base[:1] * i
            if i != 1:
                self.assertIs(review_request_grant_batch(packet, reviewed_at=NOW).status, ReviewStatus.HOLD)

    def test_atomic_batch_rejects_duplicate_claims(self):
        first, second = self._batch_pairs()
        bad_cases = (
            (first, first),
            (first, (replace(second[0], request_id=first[0].request_id), second[1])),
            (first, (second[0], replace(second[1], grant_id=first[1].grant_id))),
            (first, (second[0], replace(second[1], scope=replace(
                second[1].scope, assets=first[1].scope.assets
            )))),
        )
        for packet in bad_cases:
            with self.subTest(packet_type="duplicate"):
                result = review_request_grant_batch(packet, reviewed_at=NOW)
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)

    def test_atomic_batch_rejects_tenant_spoofing_and_partial_success(self):
        first, second = self._batch_pairs()
        other_client = "client-independent"
        cross_tenant = (
            first,
            (replace(second[0], client_id=other_client),
             replace(second[1], client_id=other_client)),
        )
        invalid_second = (first, (
            replace(second[0], status=RequestStatus.SUBMITTED), second[1]
        ))
        for packet in (cross_tenant, invalid_second):
            result = review_request_grant_batch(packet, reviewed_at=NOW)
            self.assertIs(result.status, ReviewStatus.HOLD)
            self.assert_no_authority(result)

    def test_atomic_batch_allows_separate_fully_excluded_grants(self):
        first, second = self._batch_pairs()
        # Redundant declared assets are not effective grant membership when
        # the corresponding record fully excludes them. No authority follows.
        excluded_first = (first[0], replace(first[1], scope=replace(
            first[1].scope, excluded_assets=first[1].scope.assets
        )))
        duplicate_second = (second[0], replace(second[1], scope=replace(
            second[1].scope, assets=first[1].scope.assets
        )))
        result = review_request_grant_batch(
            (excluded_first, duplicate_second), reviewed_at=NOW
        )
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_atomic_batch_is_io_free(self):
        from unittest.mock import patch
        with (
            patch("socket.socket", side_effect=AssertionError("not network")),
            patch("sqlite3.connect", side_effect=AssertionError("not sqlite")),
        ):
            result = review_request_grant_batch(self._batch_pairs(), reviewed_at=NOW)
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    @staticmethod
    def _engagement():
        return EngagementRecord(
            engagement_id="engagement-fixture",
            client_id="client-fixture",
            name="Test fixture only",
            status=EngagementStatus.AUTHORIZED,
            created_at="2030-01-30T00:00:00+00:00",
        )

    def test_engagement_three_way_match_is_only_reviewable(self):
        result = review_request_grant_engagement(
            request(), grant(), self._engagement(), reviewed_at=NOW
        )
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_engagement_claim_must_match_exact_tenant_and_id(self):
        for changes in (
            {"engagement_id": "engagement-other"},
            {"client_id": "client-other"},
            {"engagement_id": "engagement-fixture "},
            {"client_id": ""},
            {"status": "authorized"},
            {"status": EngagementStatus.DRAFT},
            {"status": EngagementStatus.AUTHORIZATION_PENDING},
            {"status": EngagementStatus.RUNNING},
            {"status": EngagementStatus.CLOSED},
            {"created_at": "2030-01-30T00:00:00Z"},
            {"created_at": "2030-01-30T00:00:00+01:00"},
            {"created_at": "2030-01-30T24:00:00+00:00"},
            {"created_at": "2030-02-02T00:00:00+00:00"},
            {"created_at": ""},
        ):
            with self.subTest(changes=changes):
                outcome = review_request_grant_engagement(
                    request(), grant(), replace(self._engagement(), **changes),
                    reviewed_at=NOW,
                )
                self.assertIs(outcome.status, ReviewStatus.HOLD)
                self.assert_no_authority(outcome)

    def test_engagement_guard_cannot_mask_untrusted_grant_time(self):
        for invalid in (None, False, "2030-01-31", datetime(2030, 1, 31)):
            with self.subTest(valid_from=invalid):
                outcome = review_request_grant_engagement(
                    request(), replace(grant(), valid_from=invalid),
                    self._engagement(), reviewed_at=NOW,
                )
                self.assertIs(outcome.status, ReviewStatus.HOLD)
                self.assert_no_authority(outcome)

    def test_engagement_rejects_fake_instances_and_after_creation_grants(self):
        class FakeEngagement(EngagementRecord):
            pass

        for engagement in (None, {}, FakeEngagement(**self._engagement().__dict__)):
            outcome = review_request_grant_engagement(
                request(), grant(), engagement, reviewed_at=NOW
            )
            self.assertIs(outcome.status, ReviewStatus.HOLD)
            self.assert_no_authority(outcome)
        after_creation = replace(
            self._engagement(), created_at=(VALID_FROM + timedelta(seconds=1)).isoformat()
        )
        outcome = review_request_grant_engagement(
            request(), grant(), after_creation, reviewed_at=NOW
        )
        self.assertIs(outcome.status, ReviewStatus.HOLD)
        self.assert_no_authority(outcome)

    def test_assembled_three_way_batch_is_always_non_authorizing(self):
        first, second = self._batch_pairs()
        packet = (
            (first[0], first[1], self._engagement()),
            (second[0], second[1], self._engagement()),
        )
        result = review_request_grant_engagement_batch(packet, reviewed_at=NOW)
        self.assertIs(result.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(result)

    def test_assembled_three_way_batch_denies_any_bad_engagement_atomically(self):
        first, second = self._batch_pairs()
        good = (first[0], first[1], self._engagement())
        for bad in (
            replace(self._engagement(), client_id="client-other"),
            replace(self._engagement(), engagement_id="engagement-other"),
            replace(self._engagement(), status=EngagementStatus.DRAFT),
            replace(self._engagement(), created_at="2030-02-02T00:00:00+00:00"),
            object(),
        ):
            with self.subTest(bad_type=type(bad).__name__):
                outcome = review_request_grant_engagement_batch(
                    (good, (second[0], second[1], bad)), reviewed_at=NOW
                )
                self.assertIs(outcome.status, ReviewStatus.HOLD)
                self.assert_no_authority(outcome)

    def test_assembled_three_way_batch_denies_all_duplicates_and_wrong_shape(self):
        first, second = self._batch_pairs()
        good1 = (first[0], first[1], self._engagement())
        good2 = (second[0], second[1], self._engagement())
        overlap_grant = replace(second[1], scope=replace(
            second[1].scope, assets=first[1].scope.assets
        ))
        packets = (
            (), [], None, ((first[0], first[1]),),
            ((first[0], first[1], self._engagement(), 0),),
            ((first[0], first[1], self._engagement()),) * 33,
            (good1, good1),
            (good1, (second[0], overlap_grant, self._engagement())),
            (good1, (second[0], replace(second[1], grant_id=first[1].grant_id), self._engagement())),
            (good1, (replace(second[0], request_id=first[0].request_id), second[1], self._engagement())),
            (good1, list(good2)),
        )
        for packet in packets:
            with self.subTest(shape=str(type(packet)), size=len(packet) if hasattr(packet, "__len__") else -1):
                result = review_request_grant_engagement_batch(packet, reviewed_at=NOW)
                self.assertIs(result.status, ReviewStatus.HOLD)
                self.assert_no_authority(result)

    def test_three_way_batch_boundary_accepts_32_separate_synthetic_rows_only(self):
        pairs = []
        for idx in range(32):
            asset = f"fixture{idx}.example.test"
            req = replace(request(), request_id=f"r{idx}", requested_assets=(asset,))
            gr = replace(
                grant(), grant_id=f"g{idx}",
                scope=replace(grant().scope, assets=(asset,))
            )
            pairs.append((req, gr, self._engagement()))
        allowed = review_request_grant_engagement_batch(tuple(pairs), reviewed_at=NOW)
        self.assertIs(allowed.status, ReviewStatus.REVIEW_ONLY)
        self.assert_no_authority(allowed)
        over = review_request_grant_engagement_batch(tuple(pairs) + (pairs[0],), reviewed_at=NOW)
        self.assertIs(over.status, ReviewStatus.HOLD)
        self.assert_no_authority(over)

    def test_result_constructor_cannot_forge_authority_flags(self):
        fields = (
            "authorized", "grant_allowed", "dispatch_allowed",
            "scan_allowed", "merge_allowed", "deploy_allowed",
        )

        class FakeBool:
            def __bool__(self):
                raise AssertionError("never ask untrusted object for truthiness")

        for field in fields:
            for invalid in (True, 1, "true", FakeBool()):
                with self.subTest(field=field, type=type(invalid).__name__):
                    with self.assertRaisesRegex(ValueError, "invalid non-authorizing review receipt"):
                        RequestGrantReview(
                            ReviewStatus.REVIEW_ONLY,
                            "structurally_coherent_untrusted_snapshot",
                            **{field: invalid},
                        )

    def test_result_constructor_cannot_forge_status_or_reason(self):
        for status, reason in (
            ("REVIEW_ONLY", "structurally_coherent_untrusted_snapshot"),
            (ReviewStatus.REVIEW_ONLY, "invalid_or_unverified_input"),
            (ReviewStatus.HOLD, "structurally_coherent_untrusted_snapshot"),
            (ReviewStatus.REVIEW_ONLY, "approved"),
            (ReviewStatus.HOLD, "secret-token-name"),
            (ReviewStatus.HOLD, None),
            (None, "invalid_or_unverified_input"),
        ):
            with self.subTest(status=status, reason=reason):
                with self.assertRaisesRegex(ValueError, "invalid non-authorizing review receipt"):
                    RequestGrantReview(status, reason)

        for status, reason in (
            (ReviewStatus.HOLD, "invalid_or_unverified_input"),
            (ReviewStatus.REVIEW_ONLY, "structurally_coherent_untrusted_snapshot"),
        ):
            candidate = RequestGrantReview(status, reason)
            self.assert_no_authority(candidate)
            with self.assertRaises((FrozenInstanceError, AttributeError)):
                candidate.authorized = True
            with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
                candidate.extra_permit = True

    def test_no_raw_input_echo_on_denial(self):
        poisoned = replace(request(), requested_assets=("secret-password.example.test",))
        result = review(req=poisoned)
        self.assert_no_authority(result)
        self.assertNotIn("secret-password", str(result))


if __name__ == "__main__":
    unittest.main()
