from __future__ import annotations

import copy
import unittest

import test_future_remediation_text_revision_request_handoff as handoff_tests
from lightup.future_remediation_text_revision_request_handoff import (
    future_remediation_text_revision_request_from_dict,
)


class FutureRemediationTextRevisionRequestSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionRequestHandoffTest(
            "test_round_trip_requires_exact_live_review_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_repeated_json_and_independent_snapshots_are_deterministic(self):
        first_json = self.request.to_json()
        second_json = self.request.to_json()
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertEqual(first_json, second_json)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["revision_checks"], second["revision_checks"])

    def test_snapshot_mutation_cannot_rewrite_typed_request_or_later_json(self):
        before_json = self.request.to_json()
        before = self.request
        before_checks = self.request.revision_checks

        snapshot = self.request.as_dict()
        snapshot["review_sha256"] = "0" * 64
        snapshot["review_decision"] = "approved"
        snapshot["revision_checks"] = tuple(reversed(snapshot["revision_checks"]))
        snapshot["execution_allowed"] = True
        snapshot["security_verdict"] = "forged"

        self.assertEqual(self.request, before)
        self.assertEqual(self.request.to_json(), before_json)
        self.assertEqual(self.request.revision_checks, before_checks)
        self.assertEqual(self.request.review_decision, "revision_required")
        self.assertFalse(self.request.execution_allowed)
        self.assertEqual(self.request.security_verdict, "not_evaluated")

    def test_untouched_programmatic_snapshot_round_trips_exactly(self):
        snapshot = self.request.as_dict()
        parsed = future_remediation_text_revision_request_from_dict(
            copy.deepcopy(snapshot)
        )

        self.assertEqual(parsed, self.request)

    def test_forged_snapshot_lineage_checks_acceptance_and_authority_fail_closed(self):
        lineage = self.request.as_dict()
        lineage["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_request_from_dict(lineage)

        checks = self.request.as_dict()
        checks["revision_checks"] = tuple(reversed(checks["revision_checks"]))
        if checks["revision_checks"] == self.request.revision_checks:
            checks["revision_checks"] = ("future_retest_separation", "unsupported_claims")
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            future_remediation_text_revision_request_from_dict(checks)

        accepted = self.request.as_dict()
        accepted["remediation_accepted"] = True
        with self.assertRaisesRegex(ValueError, "remediation_accepted"):
            future_remediation_text_revision_request_from_dict(accepted)

        widened = self.request.as_dict()
        widened["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "authority flag"):
            future_remediation_text_revision_request_from_dict(widened)

    def test_rejected_snapshot_inputs_are_not_mutated(self):
        for mutate, message in (
            (
                lambda payload: payload.__setitem__("review_sha256", "0" * 64),
                "digest mismatch",
            ),
            (
                lambda payload: payload.__setitem__(
                    "review_decision", "approved"
                ),
                "review_decision",
            ),
            (
                lambda payload: payload.__setitem__("execution_allowed", True),
                "authority flag",
            ),
        ):
            with self.subTest(message=message):
                payload = self.request.as_dict()
                mutate(payload)
                before = copy.deepcopy(payload)
                with self.assertRaisesRegex(ValueError, message):
                    future_remediation_text_revision_request_from_dict(payload)
                self.assertEqual(payload, before)

    def test_post_parse_caller_mutation_cannot_rewrite_parsed_request(self):
        caller_owned = self.request.as_dict()
        parsed = future_remediation_text_revision_request_from_dict(caller_owned)
        parsed_json = parsed.to_json()

        caller_owned["review_sha256"] = "0" * 64
        caller_owned["review_decision"] = "approved"
        caller_owned["revision_checks"] = ("caller-mutated-check",)
        caller_owned["revision_request_sha256"] = "0" * 64
        caller_owned["execution_allowed"] = True
        caller_owned["security_verdict"] = "forged"

        self.assertEqual(parsed, self.request)
        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed.revision_checks, self.request.revision_checks)
        self.assertEqual(parsed.review_decision, "revision_required")
        self.assertFalse(parsed.execution_allowed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
