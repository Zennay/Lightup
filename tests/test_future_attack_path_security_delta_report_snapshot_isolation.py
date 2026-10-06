from __future__ import annotations

import json
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureAttackPathSecurityDeltaReportSnapshotIsolationTest(unittest.TestCase):
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

    def test_json_is_byte_deterministic_and_canonical_for_all_outcomes(self):
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
                    suffix=f"snapshot-json-{classification.value}",
                )
                first = report.to_json()
                second = report.to_json()

                self.assertEqual(first, second)
                self.assertEqual(
                    first,
                    json.dumps(
                        json.loads(first),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ),
                )

    def test_mutating_producer_snapshot_cannot_change_typed_report(self):
        report = self._report(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="snapshot-detached",
        )
        baseline = report.to_json()
        original_item = report.items[0]
        snapshot = report.as_dict()

        snapshot["client_id"] = "forged-client"
        snapshot["report_complete"] = False
        snapshot["attack_path_mutation_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "pass"
        snapshot["report_sha256"] = "0" * 64
        snapshot["items"][0]["change_node_id"] = "forged-change"
        snapshot["items"][0]["classification"] = "removed"
        snapshot["items"][0]["action"] = "remove_existing_path_candidate"
        snapshot["items"][0]["evidence_ids"] = ("evidence:forged",)
        snapshot["items"][0]["capability_ids"] = ("capability:forged",)

        self.assertEqual(report.to_json(), baseline)
        self.assertNotEqual(snapshot["client_id"], report.client_id)
        self.assertTrue(report.report_complete)
        self.assertFalse(report.attack_path_mutation_allowed)
        self.assertEqual(report.future_semantics, "unresolved")
        self.assertEqual(report.security_verdict, "not_evaluated")
        self.assertEqual(report.items[0], original_item)

    def test_independent_snapshots_do_not_alias_nested_item_dicts(self):
        report = self._report(
            AttackPathTransitionClassification.WORSENED,
            suffix="snapshot-independent",
        )
        baseline = report.to_json()
        first = report.as_dict()
        second = report.as_dict()

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"][0], second["items"][0])

        first["items"][0]["subject_node_id"] = "forged-subject"
        first["items"][0]["effect_ids"] = ("effect:forged",)

        self.assertNotEqual(
            first["items"][0]["subject_node_id"],
            second["items"][0]["subject_node_id"],
        )
        self.assertNotEqual(
            first["items"][0]["effect_ids"],
            second["items"][0]["effect_ids"],
        )
        self.assertEqual(report.to_json(), baseline)

    def test_snapshot_lineage_tuple_replacement_is_caller_local(self):
        report = self._report(
            AttackPathTransitionClassification.IMPROVED,
            suffix="snapshot-lineage",
        )
        baseline = report.to_json()
        original_paths = report.items[0].current_attack_path_ids
        original_effects = report.items[0].effect_ids
        snapshot = report.as_dict()

        snapshot["items"][0]["current_attack_path_ids"] = ("path:forged",)
        snapshot["items"][0]["effect_ids"] = ("effect:forged",)
        snapshot["items"][0]["evidence_ids"] = ("evidence:forged",)

        self.assertEqual(report.items[0].current_attack_path_ids, original_paths)
        self.assertEqual(report.items[0].effect_ids, original_effects)
        self.assertEqual(report.to_json(), baseline)


if __name__ == "__main__":
    unittest.main()
