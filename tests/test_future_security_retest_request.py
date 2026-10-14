from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_remediation_retest_plan as plan_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_retest_request import (
    RETEST_REQUEST_SCHEMA_VERSION,
    FutureStateRetestPurpose,
    build_future_security_retest_request,
)


class FutureSecurityRetestRequestTest(unittest.TestCase):
    def setUp(self):
        self.p = plan_tests.FutureSecurityRemediationRetestPlanTest(
            "test_plan_is_deterministic_read_only_and_json_serializable"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _request(self, classification, *, suffix):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(classification, suffix=suffix)
        request = build_future_security_retest_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview, report, plan, request

    def test_introduced_and_worsened_become_remediation_validation_requests(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                *_, request = self._request(
                    classification,
                    suffix=f"request-{classification.value}",
                )
                self.assertEqual(len(request.items), 1)
                item = request.items[0]
                self.assertEqual(
                    item.purpose,
                    FutureStateRetestPurpose.REMEDIATION_VALIDATION,
                )
                self.assertTrue(item.remediation_required)
                self.assertTrue(request.isolated_future_state_required)
                self.assertFalse(request.execution_allowed)
                self.assertFalse(request.target_interaction_allowed)

    def test_improved_and_removed_become_verification_only_requests(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                *_, request = self._request(
                    classification,
                    suffix=f"request-{classification.value}",
                )
                item = request.items[0]
                self.assertEqual(
                    item.purpose,
                    FutureStateRetestPurpose.IMPROVEMENT_VERIFICATION,
                )
                self.assertFalse(item.remediation_required)
                self.assertFalse(request.execution_allowed)
                self.assertEqual(request.security_verdict, "not_evaluated")

    def test_insufficient_evidence_is_rejected(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="request-insufficient",
        )
        with self.assertRaisesRegex(ValueError, "evidence-complete"):
            build_future_security_retest_request(
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_tampered_plan_is_rejected_by_live_revalidation(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="request-tampered",
        )
        tampered = dataclasses.replace(plan, plan_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "remediation/retest plan is stale"):
            build_future_security_retest_request(
                tampered,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_request_is_deterministic_lineage_bound_and_read_only(self):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            first,
        ) = self._request(
            AttackPathTransitionClassification.REMOVED,
            suffix="request-deterministic",
        )
        before = dataclasses.asdict(current)
        second = build_future_security_retest_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.schema_version, RETEST_REQUEST_SCHEMA_VERSION)
        self.assertEqual(first.remediation_plan_sha256, plan.plan_sha256)
        self.assertEqual(first.report_sha256, report.report_sha256)
        self.assertEqual(first.client_id, plan.client_id)
        self.assertEqual(first.twin_id, plan.twin_id)
        self.assertEqual(first.twin_version, plan.twin_version)
        self.assertTrue(first.requested_capability_ids)
        self.assertTrue(first.evidence_ids)
        self.assertEqual(len(first.request_sha256), 64)
        int(first.request_sha256, 16)
        self.assertEqual(dataclasses.asdict(current), before)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["request_sha256"], first.request_sha256)
        self.assertEqual(exported["execution_allowed"], False)
        self.assertEqual(exported["target_interaction_allowed"], False)
        self.assertEqual(exported["isolated_future_state_required"], True)


if __name__ == "__main__":
    unittest.main()
