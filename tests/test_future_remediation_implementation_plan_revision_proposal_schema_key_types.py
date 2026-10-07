from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    future_remediation_implementation_plan_revision_proposal_from_dict,
)


class _SchemaKeyString(str):
    pass


class FutureRemediationImplementationPlanRevisionProposalSchemaKeyTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionProposalHandoffTest(
                "test_json_and_dict_round_trip_require_live_revision_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revised_plan = self.base.revised_plan

    def test_canonical_top_level_and_item_keys_are_exact_builtin_strings(self):
        payload = self.revised_plan.as_dict()

        self.assertIs(type(payload), dict)
        self.assertTrue(all(type(key) is str for key in payload))
        self.assertTrue(
            all(
                type(key) is str
                for item in payload["plan_items"]
                for key in item
            )
        )

        parsed = future_remediation_implementation_plan_revision_proposal_from_dict(
            payload
        )
        self.assertEqual(parsed, self.revised_plan)

    def test_top_level_string_subclass_key_fails_closed(self):
        payload = self.revised_plan.as_dict()
        value = payload.pop("schema_version")
        subclass_key = _SchemaKeyString("schema_version")
        payload[subclass_key] = value

        self.assertIn("schema_version", payload)
        self.assertEqual(payload["schema_version"], value)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )

        self.assertIs(
            next(key for key in payload if key == "schema_version"),
            subclass_key,
        )

    def test_nested_plan_item_string_subclass_key_fails_closed(self):
        payload = self.revised_plan.as_dict()
        item = payload["plan_items"][0]
        value = item.pop("plan_item_id")
        subclass_key = _SchemaKeyString("plan_item_id")
        item[subclass_key] = value

        self.assertIn("plan_item_id", item)
        self.assertEqual(item["plan_item_id"], value)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )

        self.assertIs(
            next(key for key in item if key == "plan_item_id"),
            subclass_key,
        )


if __name__ == "__main__":
    unittest.main()
