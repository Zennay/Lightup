from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_dict,
    future_remediation_implementation_plan_from_json,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.plan = self.base.plan

    def test_json_is_byte_deterministic_and_canonical(self):
        first = self.plan.to_json()
        second = self.plan.to_json()

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
            future_remediation_implementation_plan_from_json(first),
            self.plan,
        )

    def test_top_level_snapshot_mutation_cannot_change_source_plan(self):
        baseline = self.plan.to_json()
        snapshot = self.plan.as_dict()

        snapshot["implementation_plan_created"] = False
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "pass"
        snapshot["summary"] = "forged summary"
        for field in _AUTHORITY_FLAGS:
            snapshot[field] = True

        self.assertEqual(self.plan.to_json(), baseline)
        self.assertTrue(self.plan.implementation_plan_created)
        self.assertEqual(self.plan.future_semantics, "unresolved")
        self.assertEqual(self.plan.security_verdict, "not_evaluated")
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(self.plan, field))

    def test_nested_plan_item_snapshot_mutation_is_deeply_isolated(self):
        baseline = self.plan.to_json()
        snapshot = self.plan.as_dict()

        original_item_id = self.plan.plan_items[0].plan_item_id
        original_intent = self.plan.plan_items[0].intent
        snapshot["plan_items"][0]["plan_item_id"] = "forged-plan-item"
        snapshot["plan_items"][0]["intent"] = "forged intent"
        snapshot["plan_items"][0]["verification_intent"] = "forged verification"
        snapshot["plan_items"][0]["rollback_intent"] = "forged rollback"

        self.assertEqual(self.plan.to_json(), baseline)
        self.assertEqual(self.plan.plan_items[0].plan_item_id, original_item_id)
        self.assertEqual(self.plan.plan_items[0].intent, original_intent)
        self.assertEqual(
            future_remediation_implementation_plan_from_json(baseline),
            self.plan,
        )

    def test_reserialized_authority_forgery_fails_closed(self):
        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                snapshot = self.plan.as_dict()
                snapshot[field] = True
                forged = json.dumps(
                    snapshot,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_from_json(forged)

    def test_reserialized_future_state_or_verdict_forgery_fails_closed(self):
        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        ):
            with self.subTest(field=field):
                snapshot = self.plan.as_dict()
                snapshot[field] = value
                forged = json.dumps(
                    snapshot,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_from_json(forged)

    def test_reserialized_executable_plan_item_key_fails_closed(self):
        snapshot = self.plan.as_dict()
        snapshot["plan_items"][0]["tool_arguments"] = {"operation": "apply"}
        forged = json.dumps(
            snapshot,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_remediation_implementation_plan_from_json(forged)

    def test_repeated_snapshots_are_independent_and_strictly_parseable(self):
        first = self.plan.as_dict()
        second = self.plan.as_dict()

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first["summary"] = "mutated"
        first["plan_items"][0]["intent"] = "mutated intent"

        self.assertNotEqual(first["summary"], second["summary"])
        self.assertNotEqual(
            first["plan_items"][0]["intent"],
            second["plan_items"][0]["intent"],
        )
        self.assertEqual(
            future_remediation_implementation_plan_from_dict(second),
            self.plan,
        )


if __name__ == "__main__":
    unittest.main()
