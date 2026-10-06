from __future__ import annotations

import copy
import json
import unittest

import test_future_security_evidence_freshness_coverage_handoff as handoff_tests
from lightup.future_security_evidence_freshness_coverage import (
    future_security_evidence_freshness_coverage_from_dict,
)


_FALSE_SAFETY_FLAGS = (
    "evidence_sufficiency_evaluated",
    "gap_closed",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityEvidenceFreshnessCoverageSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = handoff_tests.FutureSecurityEvidenceFreshnessCoverageHandoffTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_to_json_is_byte_deterministic_for_covered_and_uncovered_reports(self):
        for factory in (self.base._covered_payload, self.base._uncovered_payload):
            with self.subTest(factory=factory.__name__):
                coverage, _ = factory()
                first = coverage.to_json()
                second = coverage.to_json()
                third = coverage.to_json()

                self.assertEqual(first, second)
                self.assertEqual(second, third)
                self.assertEqual(
                    future_security_evidence_freshness_coverage_from_dict(
                        json.loads(first)
                    ),
                    coverage,
                )

    def test_nested_as_dict_mutation_cannot_change_source_coverage(self):
        coverage, _ = self.base._covered_payload()
        original_json = coverage.to_json()
        snapshot = coverage.as_dict()

        snapshot["covered_gap_count"] = 0
        snapshot["all_gaps_have_fresh_candidates"] = False
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        snapshot["items"][0]["change_node_id"] = "forged-change"
        snapshot["items"][0]["candidate_evidence_ids"] = ("forged-evidence",)

        self.assertEqual(coverage.to_json(), original_json)
        self.assertEqual(coverage.covered_gap_count, 1)
        self.assertTrue(coverage.all_gaps_have_fresh_candidates)
        self.assertFalse(coverage.execution_allowed)
        self.assertEqual(coverage.future_semantics, "unresolved")
        self.assertEqual(coverage.security_verdict, "not_evaluated")
        self.assertNotEqual(coverage.items[0].change_node_id, "forged-change")

    def test_separate_as_dict_snapshots_do_not_alias_nested_items(self):
        coverage, _ = self.base._covered_payload()
        first = coverage.as_dict()
        second = coverage.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(
            first["items"][0]["candidate_evidence_ids"],
            second["items"][0]["candidate_evidence_ids"],
        )

        first["items"][0]["change_node_id"] = "changed-only-in-first"
        first["items"][0]["candidate_evidence_ids"] = ("changed-only-in-first",)

        self.assertEqual(
            second["items"][0]["change_node_id"],
            coverage.items[0].change_node_id,
        )
        self.assertEqual(
            second["items"][0]["candidate_evidence_ids"],
            coverage.items[0].candidate_evidence_ids,
        )

    def test_parser_detaches_from_covered_nested_json_containers(self):
        coverage, payload = self.base._covered_payload()
        items = payload["items"]
        item = items[0]
        evidence_ids = item["candidate_evidence_ids"]

        parsed = future_security_evidence_freshness_coverage_from_dict(payload)
        parsed_json = parsed.to_json()

        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence")
        item["change_node_id"] = "forged-change-after-parse"
        item["fresh_candidate_present"] = False
        items.append(copy.deepcopy(item))

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, coverage)
        self.assertEqual(parsed.items[0].candidate_evidence_ids, coverage.items[0].candidate_evidence_ids)
        self.assertEqual(parsed.items[0].change_node_id, coverage.items[0].change_node_id)
        self.assertTrue(parsed.items[0].fresh_candidate_present)

    def test_parser_detaches_from_uncovered_nested_json_containers(self):
        coverage, payload = self.base._uncovered_payload()
        items = payload["items"]
        item = items[0]
        evidence_ids = item["candidate_evidence_ids"]

        parsed = future_security_evidence_freshness_coverage_from_dict(payload)
        parsed_json = parsed.to_json()

        evidence_ids.append("forged-evidence-after-parse")
        item["candidate_run_id"] = "forged-run-after-parse"
        item["admission_sha256"] = "0" * 64
        items.clear()

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, coverage)
        self.assertEqual(parsed.items[0].candidate_evidence_ids, ())
        self.assertIsNone(parsed.items[0].candidate_run_id)
        self.assertIsNone(parsed.items[0].admission_sha256)
        self.assertFalse(parsed.items[0].fresh_candidate_present)

    def test_forged_coverage_authority_and_outcome_state_fail_closed(self):
        coverage, _ = self.base._covered_payload()

        for field in _FALSE_SAFETY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(coverage.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_coverage_from_dict(payload)

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(coverage.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_coverage_from_dict(payload)

    def test_snapshot_count_and_coverage_mutation_is_local_and_forgery_fails_closed(self):
        coverage, _ = self.base._uncovered_payload()
        original_json = coverage.to_json()
        snapshot = coverage.as_dict()
        snapshot["covered_gap_count"] = snapshot["total_gap_count"]
        snapshot["missing_gap_count"] = 0
        snapshot["all_gaps_have_fresh_candidates"] = True

        self.assertEqual(coverage.to_json(), original_json)
        self.assertEqual(coverage.covered_gap_count, 0)
        self.assertGreater(coverage.missing_gap_count, 0)
        self.assertFalse(coverage.all_gaps_have_fresh_candidates)

        forged = json.loads(original_json)
        forged["covered_gap_count"] = forged["total_gap_count"]
        forged["missing_gap_count"] = 0
        forged["all_gaps_have_fresh_candidates"] = True
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_coverage_from_dict(forged)


if __name__ == "__main__":
    unittest.main()
