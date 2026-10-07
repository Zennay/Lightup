from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan as plan_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_dict,
)


class FutureRemediationImplementationPlanPersistedWhitespaceCanonicalityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.plan = self.base._generate(gateway)

    @staticmethod
    def _surround(value: str) -> str:
        return f" {value} "

    def test_canonical_producer_payload_remains_valid(self):
        parsed = future_remediation_implementation_plan_from_dict(
            self.plan.as_dict()
        )

        self.assertEqual(parsed, self.plan)

    def test_persisted_top_level_text_whitespace_is_tampering_not_normalization(self):
        for field in ("provider_id", "model_id", "summary"):
            for boundary in (" ", "\t", "\n"):
                with self.subTest(field=field, boundary=repr(boundary)):
                    payload = self.plan.as_dict()
                    canonical = payload[field]
                    payload[field] = f"{boundary}{canonical}{boundary}"
                    before = dict(payload)

                    with self.assertRaises(ValueError):
                        future_remediation_implementation_plan_from_dict(payload)

                    self.assertEqual(payload, before)
                    self.assertEqual(
                        payload[field],
                        f"{boundary}{canonical}{boundary}",
                    )
                    self.assertEqual(
                        payload["plan_sha256"],
                        self.plan.plan_sha256,
                        "tamper case must retain the original persisted digest",
                    )

    def test_raw_persisted_summary_size_cannot_be_hidden_by_trimming(self):
        payload = self.plan.as_dict()
        canonical = payload["summary"]
        payload["summary"] = (" " * 4_001) + canonical
        before = dict(payload)

        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_from_dict(payload)

        self.assertEqual(payload, before)
        self.assertEqual(payload["plan_sha256"], self.plan.plan_sha256)

    def test_persisted_plan_item_text_whitespace_is_tampering_not_normalization(self):
        for field in (
            "plan_item_id",
            "intent",
            "verification_intent",
            "rollback_intent",
        ):
            with self.subTest(field=field):
                payload = self.plan.as_dict()
                item = payload["plan_items"][0]
                canonical = item[field]
                item[field] = self._surround(canonical)
                before = dict(item)

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_from_dict(payload)

                self.assertEqual(dict(item), before)
                self.assertEqual(item[field], self._surround(canonical))
                self.assertEqual(payload["plan_sha256"], self.plan.plan_sha256)

    def test_persisted_bounded_list_text_whitespace_is_tampering(self):
        exercised = 0
        for field in ("assumptions", "unresolved_questions"):
            payload = self.plan.as_dict()
            values = list(payload[field])
            if not values:
                continue
            exercised += 1
            canonical = values[0]
            values[0] = self._surround(canonical)
            payload[field] = tuple(values)
            before = tuple(payload[field])

            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_from_dict(payload)

                self.assertEqual(tuple(payload[field]), before)
                self.assertEqual(payload[field][0], self._surround(canonical))
                self.assertEqual(payload["plan_sha256"], self.plan.plan_sha256)

        self.assertGreater(
            exercised,
            0,
            "fixture must exercise at least one bounded list text field",
        )


if __name__ == "__main__":
    unittest.main()
