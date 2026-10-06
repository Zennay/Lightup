from __future__ import annotations

import copy
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
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
    future_security_remediation_retest_plan_from_json,
)


class FutureSecurityRemediationRetestPlanSnapshotIsolationTest(unittest.TestCase):
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

    def test_json_is_byte_deterministic_canonical_and_round_trips(self):
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
                    suffix=f"snapshot-json-{classification.value}",
                )
                first = plan.to_json()
                second = plan.to_json()

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
                self.assertEqual(
                    future_security_remediation_retest_plan_from_json(first),
                    plan,
                )
                self.assertEqual(
                    future_security_remediation_retest_plan_from_dict(
                        json.loads(first)
                    ),
                    plan,
                )

    def test_producer_snapshot_mutation_is_deeply_detached(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="snapshot-producer-detached",
        )
        baseline = plan.to_json()
        snapshot = plan.as_dict()

        snapshot["client_id"] = "forged-client"
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["items"][0]["change_node_id"] = "forged-change"
        snapshot["items"][0]["current_attack_path_ids"] = ("forged-path",)
        snapshot["items"][0]["evidence_ids"] = ("forged-evidence",)
        snapshot["items"][0]["capability_ids"] = ("forged-capability",)

        self.assertEqual(plan.to_json(), baseline)
        self.assertNotEqual(snapshot["client_id"], plan.client_id)
        self.assertFalse(plan.execution_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertNotEqual(
            snapshot["items"][0]["change_node_id"],
            plan.items[0].change_node_id,
        )
        self.assertNotEqual(
            snapshot["items"][0]["current_attack_path_ids"],
            plan.items[0].current_attack_path_ids,
        )

    def test_independent_producer_snapshots_do_not_alias_nested_items(self):
        plan = self._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="snapshot-independent",
        )
        baseline = plan.to_json()
        original_subject = plan.items[0].subject_node_id
        original_effects = plan.items[0].effect_ids
        first = plan.as_dict()
        second = plan.as_dict()

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])

        first["items"][0]["subject_node_id"] = "forged-subject"
        first["items"][0]["effect_ids"] = ("forged-effect",)

        self.assertNotEqual(
            first["items"][0]["subject_node_id"],
            second["items"][0]["subject_node_id"],
        )
        self.assertNotEqual(
            first["items"][0]["effect_ids"],
            second["items"][0]["effect_ids"],
        )
        self.assertEqual(plan.to_json(), baseline)
        self.assertEqual(plan.items[0].subject_node_id, original_subject)
        self.assertEqual(plan.items[0].effect_ids, original_effects)

    def test_parser_detaches_from_caller_owned_mutable_json_containers(self):
        plan = self._plan(
            AttackPathTransitionClassification.IMPROVED,
            suffix="snapshot-parser-detached",
        )
        payload = json.loads(plan.to_json())
        parsed = future_security_remediation_retest_plan_from_dict(payload)
        baseline = parsed.to_json()

        original_item_count = len(parsed.items)
        original_paths = parsed.items[0].current_attack_path_ids
        original_effects = parsed.items[0].effect_ids
        original_evidence = parsed.items[0].evidence_ids
        original_capabilities = parsed.items[0].capability_ids

        payload["client_id"] = "forged-after-parse"
        payload["items"][0]["current_attack_path_ids"].append("forged-path")
        payload["items"][0]["effect_ids"].append("forged-effect")
        payload["items"][0]["evidence_ids"].append("forged-evidence")
        payload["items"][0]["capability_ids"].append("forged-capability")
        payload["items"].append(copy.deepcopy(payload["items"][0]))

        self.assertEqual(parsed.to_json(), baseline)
        self.assertEqual(len(parsed.items), original_item_count)
        self.assertEqual(parsed.items[0].current_attack_path_ids, original_paths)
        self.assertEqual(parsed.items[0].effect_ids, original_effects)
        self.assertEqual(parsed.items[0].evidence_ids, original_evidence)
        self.assertEqual(parsed.items[0].capability_ids, original_capabilities)
        self.assertIsInstance(parsed.items, tuple)
        self.assertIsInstance(parsed.items[0].current_attack_path_ids, tuple)
        self.assertIsInstance(parsed.items[0].effect_ids, tuple)
        self.assertIsInstance(parsed.items[0].evidence_ids, tuple)
        self.assertIsInstance(parsed.items[0].capability_ids, tuple)

    def test_forged_snapshot_authority_and_future_state_fail_closed(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="snapshot-forged-top-level",
        )
        canonical = json.loads(plan.to_json())

        for field, value in (
            ("execution_allowed", True),
            ("deployment_authorized", True),
            ("attack_path_mutation_allowed", True),
            ("plan_complete", False),
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        ):
            with self.subTest(field=field):
                forged = copy.deepcopy(canonical)
                forged[field] = value
                with self.assertRaises(ValueError):
                    future_security_remediation_retest_plan_from_dict(forged)

    def test_forged_item_semantics_and_gap_readiness_fail_closed(self):
        introduced = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="snapshot-forged-item",
        )
        payload = json.loads(introduced.to_json())

        forged_action = copy.deepcopy(payload)
        forged_action["items"][0]["next_action"] = "collect_more_evidence"
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_remediation_retest_plan_from_dict(forged_action)

        forged_retest = copy.deepcopy(payload)
        forged_retest["items"][0]["future_state_retest_required"] = False
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_remediation_retest_plan_from_dict(forged_retest)

        insufficient = self._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="snapshot-forged-gap",
        )
        gap_payload = json.loads(insufficient.to_json())

        forged_gap = copy.deepcopy(gap_payload)
        forged_gap["contains_insufficient_evidence"] = False
        with self.assertRaisesRegex(ValueError, "insufficient-evidence state mismatch"):
            future_security_remediation_retest_plan_from_dict(forged_gap)

        forged_gap_action = copy.deepcopy(gap_payload)
        forged_gap_action["items"][0]["future_state_retest_required"] = True
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_remediation_retest_plan_from_dict(forged_gap_action)


if __name__ == "__main__":
    unittest.main()
