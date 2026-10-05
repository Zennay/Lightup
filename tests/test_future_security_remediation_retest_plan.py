from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    PLAN_SCHEMA_VERSION,
    FutureRemediationNextAction,
    build_future_security_remediation_retest_plan,
)


class FutureSecurityRemediationRetestPlanTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _plan(self, classification, *, suffix):
        current, proposal, context, resolution, preview = self.r._inputs(
            classification,
            suffix=suffix,
        )
        report = self.r.p and __import__(
            "lightup.future_attack_path_security_delta_report",
            fromlist=["build_future_attack_path_security_delta_report"],
        ).build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        plan = build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview, report, plan

    def test_introduced_and_worsened_require_remediation_then_retest(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                current = self.r.p.r.t.f.f.current
                before = dataclasses.asdict(current)
                *_, plan = self._plan(
                    classification,
                    suffix=f"plan-{classification.value}",
                )
                item = plan.items[0]
                self.assertEqual(
                    item.next_action,
                    FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
                )
                self.assertTrue(item.remediation_required)
                self.assertTrue(item.future_state_retest_required)
                self.assertFalse(item.evidence_required)
                self.assertEqual(plan.remediation_item_count, 1)
                self.assertEqual(plan.retest_item_count, 1)
                self.assertEqual(plan.evidence_gap_count, 0)
                self.assertEqual(dataclasses.asdict(current), before)

    def test_improved_and_removed_require_verification_retest(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                *_, plan = self._plan(
                    classification,
                    suffix=f"plan-{classification.value}",
                )
                item = plan.items[0]
                self.assertEqual(
                    item.next_action,
                    FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
                )
                self.assertFalse(item.remediation_required)
                self.assertTrue(item.future_state_retest_required)
                self.assertFalse(item.evidence_required)
                self.assertEqual(plan.remediation_item_count, 0)
                self.assertEqual(plan.retest_item_count, 1)

    def test_insufficient_evidence_blocks_retest_planning_on_more_evidence(self):
        *_, plan = self._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="plan-insufficient",
        )
        item = plan.items[0]
        self.assertEqual(
            item.next_action,
            FutureRemediationNextAction.COLLECT_MORE_EVIDENCE,
        )
        self.assertFalse(item.remediation_required)
        self.assertFalse(item.future_state_retest_required)
        self.assertTrue(item.evidence_required)
        self.assertEqual(plan.evidence_gap_count, 1)
        self.assertTrue(plan.contains_insufficient_evidence)

    def test_plan_is_deterministic_read_only_and_json_serializable(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            first,
        ) = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="plan-deterministic",
        )
        second = build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.schema_version, PLAN_SCHEMA_VERSION)
        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")
        self.assertEqual(len(first.plan_sha256), 64)
        int(first.plan_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["plan_sha256"], first.plan_sha256)
        self.assertEqual(exported["execution_allowed"], False)
        self.assertEqual(
            exported["items"][0]["classification"],
            AttackPathTransitionClassification.INTRODUCED.value,
        )

    def test_tampered_report_is_rejected_by_live_revalidation(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            _,
        ) = self._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="plan-tampered",
        )
        tampered = dataclasses.replace(report, report_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "security delta report is stale"):
            build_future_security_remediation_retest_plan(
                tampered,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
