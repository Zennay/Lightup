from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    build_future_security_remediation_retest_plan,
)
from lightup.future_security_retest_request import (
    REQUEST_SCHEMA_VERSION,
    build_future_state_retest_request,
)


class FutureStateRetestRequestTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _chain(self, classification, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            classification, suffix=suffix
        )
        args = (preview, proposal, (resolution,), (context,), self.state)
        report = build_future_attack_path_security_delta_report(*args)
        plan = build_future_security_remediation_retest_plan(report, *args)
        return plan, report, args

    def test_remediation_classes_produce_blocked_retest_items(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                plan, report, args = self._chain(
                    classification, suffix=f"req-{classification.value}"
                )
                request = build_future_state_retest_request(plan, report, *args)
                self.assertTrue(request.items[0].blocked_on_remediation)
                self.assertEqual(request.blocked_on_remediation_count, 1)
                self.assertEqual(request.retest_item_count, 1)
                self.assertEqual(request.plan_sha256, plan.plan_sha256)

    def test_verification_classes_are_not_blocked(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                plan, report, args = self._chain(
                    classification, suffix=f"req-{classification.value}"
                )
                request = build_future_state_retest_request(plan, report, *args)
                self.assertFalse(request.items[0].blocked_on_remediation)
                self.assertEqual(request.blocked_on_remediation_count, 0)

    def test_insufficient_evidence_plan_is_refused(self):
        plan, report, args = self._chain(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="req-insufficient",
        )
        with self.assertRaisesRegex(ValueError, "evidence-complete"):
            build_future_state_retest_request(plan, report, *args)

    def test_request_grants_no_rights_and_requires_all_gates(self):
        plan, report, args = self._chain(
            AttackPathTransitionClassification.INTRODUCED, suffix="req-rights"
        )
        first = build_future_state_retest_request(plan, report, *args)
        second = build_future_state_retest_request(plan, report, *args)
        self.assertEqual(first, second)
        self.assertEqual(first.schema_version, REQUEST_SCHEMA_VERSION)
        self.assertTrue(first.isolated_environment_required)
        self.assertTrue(first.scope_gate_required)
        self.assertTrue(first.authorization_gate_required)
        self.assertTrue(first.tool_policy_gate_required)
        self.assertFalse(first.real_target_interaction_allowed)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")
        exported = json.loads(first.to_json())
        self.assertEqual(exported["request_sha256"], first.request_sha256)
        self.assertEqual(len(first.request_sha256), 64)

    def test_tampered_or_stale_plan_is_rejected(self):
        plan, report, args = self._chain(
            AttackPathTransitionClassification.WORSENED, suffix="req-tamper"
        )
        for tampered in (
            dataclasses.replace(plan, plan_sha256="0" * 64),
            dataclasses.replace(plan, execution_allowed=True),
        ):
            with self.assertRaisesRegex(ValueError, "plan is stale"):
                build_future_state_retest_request(tampered, report, *args)


if __name__ == "__main__":
    unittest.main()
