from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_attack_path_graph_diff_preview as preview_tests
from lightup.future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    build_future_attack_path_graph_diff_preview,
)
from lightup.future_attack_path_security_delta_report import (
    REPORT_SCHEMA_VERSION,
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_effects import RiskDirection


class FutureAttackPathSecurityDeltaReportTest(unittest.TestCase):
    def setUp(self):
        self.p = preview_tests.FutureAttackPathGraphDiffPreviewTest(
            "test_introduced_preview_is_deterministic_and_read_only"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _inputs(
        self,
        classification: AttackPathTransitionClassification,
        *,
        suffix: str,
    ):
        existing = {
            AttackPathTransitionClassification.WORSENED: RiskDirection.INCREASED,
            AttackPathTransitionClassification.IMPROVED: RiskDirection.DECREASED,
            AttackPathTransitionClassification.REMOVED: RiskDirection.DECREASED,
        }
        if classification in existing:
            current, proposal, context, resolution = (
                self.p._existing_path_resolved_preview_input(
                    classification,
                    direction=existing[classification],
                    suffix=suffix,
                )
            )
        else:
            proposal, context, resolution = self.p._resolved_preview_input(
                classification,
                suffix=suffix,
            )
            current = self.p.r.t.f.f.current

        preview = build_future_attack_path_graph_diff_preview(
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview

    def test_all_st4_outcomes_render_exact_evidence_linked_items(self):
        cases = (
            (
                AttackPathTransitionClassification.INTRODUCED,
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
                False,
            ),
            (
                AttackPathTransitionClassification.WORSENED,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
                False,
            ),
            (
                AttackPathTransitionClassification.IMPROVED,
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
                False,
            ),
            (
                AttackPathTransitionClassification.REMOVED,
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
                False,
            ),
            (
                AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
                AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
                True,
            ),
        )
        for classification, expected_action, expected_insufficient in cases:
            with self.subTest(classification=classification.value):
                current, proposal, context, resolution, preview = self._inputs(
                    classification,
                    suffix=f"report-{classification.value}",
                )
                before = dataclasses.asdict(current)

                first = build_future_attack_path_security_delta_report(
                    preview,
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )
                second = build_future_attack_path_security_delta_report(
                    preview,
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )

                self.assertEqual(first, second)
                self.assertEqual(first.schema_version, REPORT_SCHEMA_VERSION)
                self.assertEqual(first.preview_sha256, preview.preview_sha256)
                self.assertEqual(first.items[0].classification, classification)
                self.assertEqual(first.items[0].action, expected_action)
                self.assertEqual(first.items[0].evidence_ids, resolution.evidence_ids)
                self.assertEqual(
                    first.items[0].capability_ids,
                    resolution.capability_ids,
                )
                self.assertEqual(
                    first.contains_insufficient_evidence,
                    expected_insufficient,
                )
                self.assertTrue(first.report_complete)
                self.assertFalse(first.attack_path_mutation_allowed)
                self.assertEqual(first.future_semantics, "unresolved")
                self.assertEqual(first.security_verdict, "not_evaluated")
                self.assertEqual(len(first.report_sha256), 64)
                int(first.report_sha256, 16)
                self.assertEqual(dataclasses.asdict(current), before)

                exported = json.loads(first.to_json())
                self.assertEqual(exported["preview_sha256"], preview.preview_sha256)
                self.assertEqual(
                    exported["items"][0]["classification"],
                    classification.value,
                )
                self.assertEqual(
                    exported["items"][0]["action"],
                    expected_action.value,
                )

    def test_tampered_serialized_preview_is_rejected_by_live_revalidation(self):
        _, proposal, context, resolution, preview = self._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="report-tamper",
        )
        tampered_item = dataclasses.replace(
            preview.items[0],
            evidence_ids=preview.items[0].evidence_ids + ("evidence:forged",),
        )
        tampered = dataclasses.replace(
            preview,
            items=(tampered_item,),
        )

        with self.assertRaisesRegex(
            ValueError,
            "live validated lineage",
        ):
            build_future_attack_path_security_delta_report(
                tampered,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_stale_or_mismatched_resolution_lineage_is_rejected(self):
        _, proposal, context, resolution, preview = self._inputs(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="report-stale-resolution",
        )
        stale_resolution = dataclasses.replace(
            resolution,
            resolution_sha256="0" * 64,
        )

        with self.assertRaises(ValueError):
            build_future_attack_path_security_delta_report(
                preview,
                proposal,
                (stale_resolution,),
                (context,),
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
