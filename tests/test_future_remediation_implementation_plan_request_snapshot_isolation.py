from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_dict,
    future_remediation_implementation_plan_request_from_json,
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


class FutureRemediationImplementationPlanningRequestSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanRequestHandoffTest(
            "test_round_trip_requires_exact_live_accepted_review"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_json_is_byte_deterministic_and_canonical(self):
        first = self.request.to_json()
        second = self.request.to_json()

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
            future_remediation_implementation_plan_request_from_json(first),
            self.request,
        )

    def test_snapshot_mutation_cannot_change_source_request(self):
        baseline = self.request.to_json()
        snapshot = self.request.as_dict()

        snapshot["implementation_planning_requested"] = False
        snapshot["implementation_plan_created"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "pass"
        snapshot["item_count"] = 999
        for field in _AUTHORITY_FLAGS:
            snapshot[field] = True

        self.assertEqual(self.request.to_json(), baseline)
        self.assertTrue(self.request.implementation_planning_requested)
        self.assertFalse(self.request.implementation_plan_created)
        self.assertEqual(self.request.future_semantics, "unresolved")
        self.assertEqual(self.request.security_verdict, "not_evaluated")
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(self.request, field))

    def test_reserialized_lifecycle_and_authority_forgery_fails_closed(self):
        lifecycle_cases = (
            ("implementation_planning_requested", False),
            ("implementation_plan_created", True),
            ("future_semantics", "resolved"),
            ("security_verdict", "pass"),
        )
        for field, value in lifecycle_cases:
            with self.subTest(field=field):
                snapshot = self.request.as_dict()
                snapshot[field] = value
                forged = json.dumps(
                    snapshot,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_request_from_json(forged)

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                snapshot = self.request.as_dict()
                snapshot[field] = True
                forged = json.dumps(
                    snapshot,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_request_from_json(forged)

    def test_reserialized_lineage_or_schema_forgery_fails_closed(self):
        digest_forged = self.request.as_dict()
        digest_forged["review_sha256"] = (
            "0" * 64
            if self.request.review_sha256 != "0" * 64
            else "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_request_from_dict(digest_forged)

        schema_forged = self.request.as_dict()
        schema_forged["tool_arguments"] = {"operation": "apply"}
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_request_from_dict(schema_forged)

    def test_repeated_snapshots_are_independent_and_strictly_parseable(self):
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertEqual(first, second)
        self.assertIsNot(first, second)

        first["implementation_plan_created"] = True
        first["reviewer_model_id"] = "forged-model"
        self.assertFalse(second["implementation_plan_created"])
        self.assertEqual(second["reviewer_model_id"], self.request.reviewer_model_id)
        self.assertEqual(
            future_remediation_implementation_plan_request_from_dict(second),
            self.request,
        )


if __name__ == "__main__":
    unittest.main()
