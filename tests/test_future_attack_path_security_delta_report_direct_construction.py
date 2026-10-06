from __future__ import annotations

import dataclasses
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureAttackPathSecurityDeltaReportDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _report(self, classification, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            classification,
            suffix=suffix,
        )
        return build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_canonical_builder_outputs_remain_valid_for_all_st4_outcomes(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        ):
            with self.subTest(classification=classification.value):
                report = self._report(
                    classification,
                    suffix=f"direct-valid-{classification.value}",
                )
                self.assertTrue(report.report_complete)
                self.assertFalse(report.attack_path_mutation_allowed)
                self.assertEqual(report.future_semantics, "unresolved")
                self.assertEqual(report.security_verdict, "not_evaluated")

    def test_direct_report_stop_line_widening_fails_closed(self):
        report = self._report(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-stop-line",
        )
        for field, value in (
            ("report_complete", False),
            ("report_complete", 1),
            ("attack_path_mutation_allowed", True),
            ("attack_path_mutation_allowed", 0),
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    dataclasses.replace(report, **{field: value})

    def test_direct_report_structure_and_digest_tampering_fails_closed(self):
        report = self._report(
            AttackPathTransitionClassification.WORSENED,
            suffix="direct-report-structure",
        )
        mutations = (
            ("schema_version", "st4.security_delta.v999"),
            ("client_id", ""),
            ("current_twin_version", True),
            ("twin_version", -1),
            ("proposal_sha256", "A" * 64),
            ("items", list(report.items)),
            ("contains_insufficient_evidence", True),
            ("report_sha256", "A" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(report, **{field: value})

    def test_stale_canonical_digest_remains_constructible_for_live_consumer_tests(self):
        report = self._report(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-stale-digest",
        )
        stale = dataclasses.replace(report, report_sha256="0" * 64)
        self.assertEqual(stale.report_sha256, "0" * 64)
        self.assertNotEqual(stale, report)

    def test_direct_item_requires_exact_enum_and_classification_action_pair(self):
        report = self._report(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="direct-item-action",
        )
        item = report.items[0]

        with self.assertRaisesRegex(ValueError, "classification must be an enum"):
            dataclasses.replace(item, classification=item.classification.value)
        with self.assertRaisesRegex(ValueError, "action must be an enum"):
            dataclasses.replace(item, action=item.action.value)
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            dataclasses.replace(
                item,
                action=AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
            )

    def test_direct_item_identity_digest_and_lineage_types_fail_closed(self):
        report = self._report(
            AttackPathTransitionClassification.IMPROVED,
            suffix="direct-item-types",
        )
        item = report.items[0]

        for field, value in (
            ("change_node_id", ""),
            ("subject_node_id", ""),
            ("resolution_id", ""),
            ("resolution_sha256", "A" * 64),
            ("effect_ids", list(item.effect_ids)),
            ("current_attack_path_ids", list(item.current_attack_path_ids)),
            ("evidence_ids", list(item.evidence_ids)),
            ("capability_ids", list(item.capability_ids)),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(item, **{field: value})

        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            dataclasses.replace(
                item,
                evidence_ids=("evidence:duplicate", "evidence:duplicate"),
            )
        with self.assertRaisesRegex(ValueError, "non-empty strings"):
            dataclasses.replace(item, capability_ids=("",))

    def test_direct_report_rejects_duplicate_change_and_resolution_identity(self):
        report = self._report(
            AttackPathTransitionClassification.WORSENED,
            suffix="direct-identity",
        )
        item = report.items[0]

        with self.assertRaisesRegex(ValueError, "duplicate changes"):
            dataclasses.replace(report, items=(item, item))

        same_change_new_resolution = dataclasses.replace(
            item,
            resolution_id=f"{item.resolution_id}:other",
        )
        with self.assertRaisesRegex(ValueError, "duplicate changes"):
            dataclasses.replace(report, items=(item, same_change_new_resolution))

        new_change_same_resolution = dataclasses.replace(
            item,
            change_node_id=f"{item.change_node_id}:other",
        )
        with self.assertRaisesRegex(ValueError, "duplicate resolutions"):
            dataclasses.replace(report, items=(item, new_change_same_resolution))

    def test_direct_report_rejects_cross_change_current_path_collision(self):
        report = self._report(
            AttackPathTransitionClassification.WORSENED,
            suffix="direct-path-collision",
        )
        item = report.items[0]
        self.assertTrue(item.current_attack_path_ids)

        second = dataclasses.replace(
            item,
            change_node_id=f"{item.change_node_id}:other",
            resolution_id=f"{item.resolution_id}:other",
        )
        with self.assertRaisesRegex(ValueError, "colliding current attack path claims"):
            dataclasses.replace(report, items=(item, second))

    def test_insufficient_evidence_state_is_derived_from_items(self):
        report = self._report(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="direct-insufficient",
        )
        self.assertTrue(report.contains_insufficient_evidence)
        with self.assertRaisesRegex(ValueError, "insufficient-evidence state"):
            dataclasses.replace(report, contains_insufficient_evidence=False)


if __name__ == "__main__":
    unittest.main()
