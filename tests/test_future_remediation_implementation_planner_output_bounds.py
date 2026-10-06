from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan as plan_tests


class FutureRemediationImplementationPlannerOutputBoundsTest(unittest.TestCase):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _generate_from_payload(self, payload):
        gateway, provider = self.base._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        return gateway, provider

    def test_canonical_output_remains_bounded_and_non_executable(self):
        gateway, _ = self.base._gateway()
        plan = self.base._generate(gateway)

        self.assertTrue(plan.implementation_plan_created)
        self.assertFalse(plan.code_change_authorized)
        self.assertFalse(plan.tool_call_created)
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.target_interaction_allowed)
        self.assertFalse(plan.future_state_retest_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)

    def test_summary_rejects_empty_nul_and_oversize_text(self):
        cases = (
            ("", "non-empty string"),
            ("   ", "non-empty string"),
            ("safe\x00unsafe", "contains NUL"),
            ("x" * 4001, "bounded size"),
        )
        for value, message in cases:
            with self.subTest(message=message):
                payload = json.loads(plan_tests._plan_json())
                payload["summary"] = value
                gateway, provider = self._generate_from_payload(payload)

                with self.assertRaisesRegex(ValueError, message):
                    self.base._generate(gateway)

                self.assertEqual(len(provider.requests), 1)

    def test_plan_item_count_is_non_empty_and_bounded(self):
        payload = json.loads(plan_tests._plan_json())
        payload["plan_items"] = []
        gateway, _ = self._generate_from_payload(payload)
        with self.assertRaisesRegex(ValueError, "at least one plan item"):
            self.base._generate(gateway)

        payload = json.loads(plan_tests._plan_json())
        item = payload["plan_items"][0]
        payload["plan_items"] = [
            {**item, "plan_item_id": f"plan-{index}"}
            for index in range(21)
        ]
        gateway, _ = self._generate_from_payload(payload)
        with self.assertRaisesRegex(ValueError, "bounded item count"):
            self.base._generate(gateway)

    def test_plan_item_text_fields_are_bounded_and_nul_free(self):
        for field in ("intent", "verification_intent", "rollback_intent"):
            with self.subTest(field=field, case="oversize"):
                payload = json.loads(plan_tests._plan_json())
                payload["plan_items"][0][field] = "x" * 1201
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "bounded size"):
                    self.base._generate(gateway)

            with self.subTest(field=field, case="nul"):
                payload = json.loads(plan_tests._plan_json())
                payload["plan_items"][0][field] = "safe\x00unsafe"
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "contains NUL"):
                    self.base._generate(gateway)

    def test_plan_item_id_is_bounded_and_non_empty(self):
        for value, message in (
            ("", "non-empty string"),
            (" " * 4, "non-empty string"),
            ("x" * 129, "bounded size"),
        ):
            with self.subTest(message=message):
                payload = json.loads(plan_tests._plan_json())
                payload["plan_items"][0]["plan_item_id"] = value
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, message):
                    self.base._generate(gateway)

    def test_surrounding_whitespace_normalizes_to_same_plan_digest(self):
        clean_gateway, _ = self.base._gateway()
        clean = self.base._generate(clean_gateway)

        payload = json.loads(plan_tests._plan_json())
        payload["summary"] = "  " + payload["summary"] + "  "
        for field in ("plan_item_id", "intent", "verification_intent", "rollback_intent"):
            payload["plan_items"][0][field] = (
                "  " + payload["plan_items"][0][field] + "  "
            )
        payload["assumptions"] = [
            "  " + item + "  " for item in payload["assumptions"]
        ]

        padded_gateway, _ = self._generate_from_payload(payload)
        padded = self.base._generate(padded_gateway)

        self.assertEqual(padded.summary, clean.summary)
        self.assertEqual(padded.plan_items, clean.plan_items)
        self.assertEqual(padded.assumptions, clean.assumptions)
        self.assertEqual(padded.unresolved_questions, clean.unresolved_questions)
        self.assertEqual(padded.plan_sha256, clean.plan_sha256)

    def test_assumptions_and_questions_require_bounded_lists(self):
        for field in ("assumptions", "unresolved_questions"):
            with self.subTest(field=field, case="type"):
                payload = json.loads(plan_tests._plan_json())
                payload[field] = "not-a-list"
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "must be a list"):
                    self.base._generate(gateway)

            with self.subTest(field=field, case="count"):
                payload = json.loads(plan_tests._plan_json())
                payload[field] = [f"item-{index}" for index in range(21)]
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "bounded item count"):
                    self.base._generate(gateway)

            with self.subTest(field=field, case="text"):
                payload = json.loads(plan_tests._plan_json())
                payload[field] = ["x" * 801]
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "bounded size"):
                    self.base._generate(gateway)

            with self.subTest(field=field, case="empty"):
                payload = json.loads(plan_tests._plan_json())
                payload[field] = ["   "]
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    self.base._generate(gateway)

            with self.subTest(field=field, case="nul"):
                payload = json.loads(plan_tests._plan_json())
                payload[field] = ["safe\x00unsafe"]
                gateway, _ = self._generate_from_payload(payload)
                with self.assertRaisesRegex(ValueError, "contains NUL"):
                    self.base._generate(gateway)


if __name__ == "__main__":
    unittest.main()
