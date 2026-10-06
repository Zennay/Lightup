from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_coverage_handoff as handoff_tests
from lightup.future_security_evidence_freshness_coverage import (
    future_security_evidence_freshness_coverage_from_dict,
)


_SAFETY_FALSE_FIELDS = (
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
        self.handoff = handoff_tests.FutureSecurityEvidenceFreshnessCoverageHandoffTest(
            "test_exact_round_trip_restores_covered_and_uncovered_reports"
        )
        self.handoff.setUp()
        self.addCleanup(self.handoff.tearDown)
        self.coverage, _ = self.handoff._covered_payload()

    def _persisted_dict(self):
        return json.loads(self.coverage.to_json())

    def test_json_is_byte_deterministic_and_json_derived_dict_round_trips(self):
        first = self.coverage.to_json()
        second = self.coverage.to_json()
        third = self.coverage.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        restored = future_security_evidence_freshness_coverage_from_dict(
            json.loads(first)
        )
        self.assertEqual(restored, self.coverage)

    def test_producer_snapshot_nested_mutation_cannot_change_source_coverage(self):
        original_json = self.coverage.to_json()
        snapshot = self.coverage.as_dict()

        snapshot["covered_gap_count"] = 0
        snapshot["missing_gap_count"] = snapshot["total_gap_count"]
        snapshot["all_gaps_have_fresh_candidates"] = False
        snapshot["gap_closed"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        snapshot["items"][0]["source_resolution_id"] = "forged-resolution"
        snapshot["items"][0]["candidate_evidence_ids"] = ("forged-evidence",)

        self.assertEqual(self.coverage.to_json(), original_json)
        self.assertTrue(self.coverage.all_gaps_have_fresh_candidates)
        self.assertEqual(self.coverage.covered_gap_count, self.coverage.total_gap_count)
        self.assertEqual(self.coverage.missing_gap_count, 0)
        self.assertFalse(self.coverage.gap_closed)
        self.assertFalse(self.coverage.execution_allowed)
        self.assertEqual(self.coverage.future_semantics, "unresolved")
        self.assertEqual(self.coverage.security_verdict, "not_evaluated")

    def test_independent_producer_snapshots_do_not_alias_nested_state(self):
        first = self.coverage.as_dict()
        second = self.coverage.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(
            first["items"][0]["candidate_evidence_ids"],
            second["items"][0]["candidate_evidence_ids"],
        )

        first["items"][0]["source_resolution_id"] = "changed-only-in-first"
        first["items"][0]["candidate_evidence_ids"] = ("changed-only-in-first",)

        self.assertNotEqual(
            first["items"][0]["source_resolution_id"],
            second["items"][0]["source_resolution_id"],
        )
        self.assertNotEqual(
            first["items"][0]["candidate_evidence_ids"],
            second["items"][0]["candidate_evidence_ids"],
        )

    def test_parser_detaches_from_mutable_nested_persisted_state(self):
        persisted = self._persisted_dict()
        items = persisted["items"]
        first_item = items[0]
        evidence_ids = first_item["candidate_evidence_ids"]

        parsed = future_security_evidence_freshness_coverage_from_dict(persisted)
        parsed_json = parsed.to_json()

        first_item["source_resolution_id"] = "forged-after-parse"
        evidence_ids[0] = "forged-evidence-after-parse"
        evidence_ids.append("extra-evidence-after-parse")
        items.append(dict(first_item))
        persisted["covered_gap_count"] = 0
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.coverage)
        self.assertNotIn(
            "forged-evidence-after-parse",
            parsed.items[0].candidate_evidence_ids,
        )
        self.assertFalse(parsed.execution_allowed)

    def test_forged_counts_coverage_and_safety_state_fail_closed(self):
        mutations = {
            "covered_gap_count": 0,
            "missing_gap_count": self.coverage.total_gap_count,
            "all_gaps_have_fresh_candidates": False,
            "future_semantics": "resolved",
            "security_verdict": "secure",
        }
        for field in _SAFETY_FALSE_FIELDS:
            mutations[field] = True

        for field, value in mutations.items():
            with self.subTest(field=field):
                persisted = self._persisted_dict()
                persisted[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_coverage_from_dict(
                        persisted
                    )

    def test_forged_nested_candidate_state_fails_closed(self):
        duplicate = self._persisted_dict()
        evidence_id = duplicate["items"][0]["candidate_evidence_ids"][0]
        duplicate["items"][0]["candidate_evidence_ids"].append(evidence_id)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_freshness_coverage_from_dict(duplicate)

        missing_run = self._persisted_dict()
        missing_run["items"][0]["candidate_run_id"] = None
        with self.assertRaises(ValueError):
            future_security_evidence_freshness_coverage_from_dict(missing_run)

        forged_digest = self._persisted_dict()
        forged_digest["items"][0]["admission_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_evidence_freshness_coverage_from_dict(forged_digest)

    def test_post_parse_top_level_mutation_cannot_change_typed_coverage(self):
        persisted = self._persisted_dict()
        parsed = future_security_evidence_freshness_coverage_from_dict(persisted)
        parsed_json = parsed.to_json()

        persisted["client_id"] = "changed-after-parse"
        persisted["coverage_sha256"] = "0" * 64
        persisted["gap_closed"] = True
        persisted["security_verdict"] = "secure"

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.coverage)
        self.assertFalse(parsed.gap_closed)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
