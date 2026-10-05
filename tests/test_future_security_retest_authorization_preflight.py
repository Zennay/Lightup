from __future__ import annotations

import dataclasses
import json
import unittest
from datetime import datetime, timedelta, timezone

import test_future_security_retest_request as request_tests
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_authorization_preflight import (
    RETEST_AUTHORIZATION_PREFLIGHT_SCHEMA_VERSION,
    FutureRetestAuthorizationStatus,
    FutureSecurityRetestAssetBinding,
    build_future_security_retest_authorization_preflight,
)


class FutureSecurityRetestAuthorizationPreflightTest(unittest.TestCase):
    def setUp(self):
        self.r = request_tests.FutureSecurityRetestRequestTest(
            "test_request_is_deterministic_lineage_bound_and_read_only"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state
        self.checked_at = datetime(2026, 10, 5, 20, 0, tzinfo=timezone.utc)

    def _inputs(self, *, suffix="auth-preflight"):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.r._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix=suffix,
        )
        asset = "future-app.example.test"
        binding = FutureSecurityRetestAssetBinding(
            resolution_id=request.items[0].resolution_id,
            asset=asset,
        )
        grant = AuthorizationGrant(
            grant_id=f"grant-{suffix}",
            client_id=request.client_id,
            engagement_id=context.engagement_id,
            approved_by="security-owner@example.test",
            reference=f"signed-roe-{suffix}",
            scope=ScopeDefinition(
                assets=(asset,),
                max_risk=RiskLevel.STANDARD,
                allowed_capabilities=request.requested_capability_ids,
            ),
            valid_from=self.checked_at - timedelta(hours=1),
            valid_until=self.checked_at + timedelta(hours=1),
            recurring_retest_allowed=True,
        )
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        )

    def _build(self, *, suffix="auth-preflight", binding_override=None, grant_override=None):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        ) = self._inputs(suffix=suffix)
        bindings = (binding,) if binding_override is None else binding_override
        authorization = grant if grant_override is None else grant_override
        result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            authorization,
            bindings,
            self.checked_at,
        )
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            result,
        )

    def test_valid_recurring_grant_is_eligible_only_for_later_policy_review(self):
        *_, request, binding, grant, preflight = self._build(suffix="auth-valid")
        self.assertEqual(
            preflight.status,
            FutureRetestAuthorizationStatus.ELIGIBLE_FOR_TOOL_POLICY_REVIEW,
        )
        self.assertTrue(preflight.eligible_for_tool_policy_review)
        self.assertTrue(preflight.tool_policy_review_required)
        self.assertFalse(preflight.execution_allowed)
        self.assertFalse(preflight.target_interaction_allowed)
        self.assertFalse(preflight.deployment_authorized)
        self.assertFalse(preflight.attack_path_mutation_allowed)
        self.assertEqual(preflight.future_semantics, "unresolved")
        self.assertEqual(preflight.security_verdict, "not_evaluated")
        self.assertEqual(preflight.request_sha256, request.request_sha256)
        self.assertEqual(preflight.authorization_grant_id, grant.grant_id)
        self.assertEqual(preflight.bindings, (binding,))

    def test_missing_duplicate_and_wildcard_bindings_fail_closed(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        ) = self._inputs(suffix="auth-bindings")

        with self.assertRaisesRegex(ValueError, "cover every retest item exactly once"):
            build_future_security_retest_authorization_preflight(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (),
                self.checked_at,
            )

        with self.assertRaisesRegex(ValueError, "duplicate asset binding"):
            build_future_security_retest_authorization_preflight(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding, binding),
                self.checked_at,
            )

        wildcard = dataclasses.replace(binding, asset="*.example.test")
        wildcard_grant = dataclasses.replace(
            grant,
            scope=dataclasses.replace(grant.scope, assets=("*.example.test",)),
        )
        with self.assertRaisesRegex(ValueError, "without wildcards"):
            build_future_security_retest_authorization_preflight(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                wildcard_grant,
                (wildcard,),
                self.checked_at,
            )

    def test_cross_client_and_tampered_request_are_rejected(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        ) = self._inputs(suffix="auth-integrity")

        tampered = dataclasses.replace(request, request_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "retest request is stale"):
            build_future_security_retest_authorization_preflight(
                tampered,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                grant,
                (binding,),
                self.checked_at,
            )

        cross_client = dataclasses.replace(grant, client_id="other-client")
        with self.assertRaisesRegex(ValueError, "grant client does not match"):
            build_future_security_retest_authorization_preflight(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
                cross_client,
                (binding,),
                self.checked_at,
            )

    def test_malformed_authorization_provenance_is_rejected(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        ) = self._inputs(suffix="auth-provenance")

        malformed_grants = (
            (dataclasses.replace(grant, grant_id=""), "non-empty grant_id"),
            (dataclasses.replace(grant, approved_by="   "), "non-empty approved_by"),
            (dataclasses.replace(grant, reference=""), "non-empty reference"),
            (
                dataclasses.replace(
                    grant,
                    valid_from=self.checked_at.replace(tzinfo=None),
                ),
                "valid_from must be timezone-aware",
            ),
            (
                dataclasses.replace(
                    grant,
                    valid_until=self.checked_at.replace(tzinfo=None),
                ),
                "valid_until must be timezone-aware",
            ),
            (
                dataclasses.replace(
                    grant,
                    valid_from=self.checked_at + timedelta(hours=2),
                    valid_until=self.checked_at + timedelta(hours=1),
                ),
                "validity window is inverted",
            ),
        )

        for malformed, expected in malformed_grants:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(ValueError, expected):
                    build_future_security_retest_authorization_preflight(
                        request,
                        plan,
                        report,
                        preview,
                        proposal,
                        (resolution,),
                        (context,),
                        self.state,
                        malformed,
                        (binding,),
                        self.checked_at,
                    )

    def test_expired_and_non_recurring_grants_require_reauthorization(self):
        *base, grant, _ = self._build(suffix="auth-window")
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
        ) = base

        expired = dataclasses.replace(
            grant,
            valid_from=self.checked_at - timedelta(hours=2),
            valid_until=self.checked_at - timedelta(minutes=1),
        )
        expired_result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            expired,
            (binding,),
            self.checked_at,
        )
        self.assertEqual(
            expired_result.status,
            FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED,
        )
        self.assertIn("authorization_not_current", expired_result.reasons)
        self.assertFalse(expired_result.eligible_for_tool_policy_review)

        non_recurring = dataclasses.replace(grant, recurring_retest_allowed=False)
        non_recurring_result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            non_recurring,
            (binding,),
            self.checked_at,
        )
        self.assertEqual(
            non_recurring_result.status,
            FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED,
        )
        self.assertIn("recurring_retest_not_authorized", non_recurring_result.reasons)

    def test_out_of_scope_asset_and_capability_require_reauthorization(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
        ) = self._inputs(suffix="auth-scope")

        asset_miss = dataclasses.replace(
            grant,
            scope=dataclasses.replace(grant.scope, assets=("different.example.test",)),
        )
        asset_result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            asset_miss,
            (binding,),
            self.checked_at,
        )
        self.assertEqual(
            asset_result.status,
            FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED,
        )
        self.assertTrue(
            any(reason.startswith("asset_out_of_scope:") for reason in asset_result.reasons)
        )

        capability_miss = dataclasses.replace(
            grant,
            scope=dataclasses.replace(
                grant.scope,
                allowed_capabilities=("different-capability",),
            ),
        )
        capability_result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            capability_miss,
            (binding,),
            self.checked_at,
        )
        self.assertEqual(
            capability_result.status,
            FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED,
        )
        self.assertTrue(
            any(
                reason.startswith("capability_out_of_scope:")
                for reason in capability_result.reasons
            )
        )

        implicit_allow_all = dataclasses.replace(
            grant,
            scope=dataclasses.replace(
                grant.scope,
                allowed_capabilities=(),
            ),
        )
        implicit_allow_all_result = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            implicit_allow_all,
            (binding,),
            self.checked_at,
        )
        self.assertEqual(
            implicit_allow_all_result.status,
            FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED,
        )
        self.assertTrue(
            any(
                reason.startswith("capability_out_of_scope:")
                for reason in implicit_allow_all_result.reasons
            )
        )

    def test_preflight_is_deterministic_and_json_serializable(self):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            binding,
            grant,
            first,
        ) = self._build(suffix="auth-deterministic")
        before = dataclasses.asdict(current)
        second = build_future_security_retest_authorization_preflight(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
            grant,
            (binding,),
            self.checked_at,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first.schema_version,
            RETEST_AUTHORIZATION_PREFLIGHT_SCHEMA_VERSION,
        )
        self.assertEqual(len(first.preflight_sha256), 64)
        int(first.preflight_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["preflight_sha256"], first.preflight_sha256)
        self.assertEqual(exported["status"], first.status.value)
        self.assertEqual(exported["execution_allowed"], False)
        self.assertEqual(exported["tool_policy_review_required"], True)


if __name__ == "__main__":
    unittest.main()
