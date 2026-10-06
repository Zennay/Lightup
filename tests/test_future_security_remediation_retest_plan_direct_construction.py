from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    FutureRemediationNextAction,
    build_future_security_remediation_retest_plan,
)


class FutureSecurityRemediationRetestPlanDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _plan(self, classification, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            classification,
            suffix=suffix,
        )
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_canonical_builder_outputs_remain_valid_for_every_classification(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        ):
            with self.subTest(classification=classification.value):
                plan = self._plan(
                    classification,
                    suffix=f"direct-valid-{classification.value}",
                )
                self.assertTrue(plan.plan_complete)
                self.assertFalse(plan.execution_allowed)
                self.assertFalse(plan.deployment_authorized)
                self.assertFalse(plan.attack_path_mutation_allowed)
                self.assertEqual(plan.future_semantics, "unresolved")
                self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_direct_plan_authority_and_lifecycle_widening_fail_closed(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-authority",
        )
        for field, value in (
            ("plan_complete", False),
            ("plan_complete", 1),
            ("execution_allowed", True),
            ("execution_allowed", 0),
            ("deployment_authorized", True),
            ("attack_path_mutation_allowed", True),
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    dataclasses.replace(plan, **{field: value})

    def test_direct_plan_structure_counts_and_digest_fail_closed(self):
        plan = self._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="direct-structure",
        )
        mutations = (
            ("schema_version", "st5.remediation_retest_plan.v999"),
            ("client_id", ""),
            ("current_twin_version", True),
            ("twin_version", -1),
            ("report_sha256", "A" * 64),
            ("items", list(plan.items)),
            ("remediation_item_count", plan.remediation_item_count + 1),
            ("retest_item_count", plan.retest_item_count + 1),
            ("evidence_gap_count", plan.evidence_gap_count + 1),
            ("contains_insufficient_evidence", True),
            ("plan_sha256", "A" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(plan, **{field: value})

    def test_stale_canonical_digest_remains_constructible_for_live_consumers(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-stale-plan-digest",
        )
        stale = dataclasses.replace(plan, plan_sha256="0" * 64)
        self.assertEqual(stale.plan_sha256, "0" * 64)
        self.assertNotEqual(stale, plan)

    def test_direct_item_identity_enum_and_boolean_confusion_fail_closed(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-item-types",
        )
        item = plan.items[0]
        mutations = (
            ("change_node_id", ""),
            ("resolution_sha256", "A" * 64),
            ("classification", AttackPathTransitionClassification.INTRODUCED.value),
            ("graph_diff_action", item.graph_diff_action.value),
            ("next_action", item.next_action.value),
            ("remediation_required", 1),
            ("future_state_retest_required", 1),
            ("evidence_required", 0),
            ("current_attack_path_ids", list(item.current_attack_path_ids)),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(item, **{field: value})

    def test_direct_item_action_semantics_cannot_be_forged(self):
        introduced = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-item-semantics",
        ).items[0]

        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            dataclasses.replace(
                introduced,
                next_action=FutureRemediationNextAction.COLLECT_MORE_EVIDENCE,
            )
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            dataclasses.replace(introduced, remediation_required=False)
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            dataclasses.replace(introduced, future_state_retest_required=False)
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            dataclasses.replace(introduced, evidence_required=True)

    def test_direct_item_lineage_containers_must_be_tuple_unique_strings(self):
        plan = self._plan(
            AttackPathTransitionClassification.IMPROVED,
            suffix="direct-item-lineage",
        )
        item = plan.items[0]

        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field, case="list"):
                with self.assertRaisesRegex(ValueError, "must be a tuple"):
                    dataclasses.replace(item, **{field: list(getattr(item, field))})

        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            dataclasses.replace(
                item,
                capability_ids=("duplicate-capability", "duplicate-capability"),
            )
        with self.assertRaisesRegex(ValueError, "non-empty strings"):
            dataclasses.replace(item, evidence_ids=("",))

    def test_direct_plan_duplicate_item_identity_fails_before_digest_reuse(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-duplicate",
        )
        with self.assertRaisesRegex(ValueError, "identity must be unique"):
            dataclasses.replace(
                plan,
                items=(plan.items[0], plan.items[0]),
                remediation_item_count=2,
                retest_item_count=2,
            )

    def test_insufficient_evidence_state_is_derived_not_claimed(self):
        plan = self._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="direct-gap",
        )
        self.assertTrue(plan.contains_insufficient_evidence)
        self.assertEqual(plan.evidence_gap_count, 1)

        with self.assertRaisesRegex(ValueError, "insufficient-evidence state mismatch"):
            dataclasses.replace(plan, contains_insufficient_evidence=False)
        with self.assertRaisesRegex(ValueError, "evidence-gap count mismatch"):
            dataclasses.replace(plan, evidence_gap_count=0)


if __name__ == "__main__":
    unittest.main()
