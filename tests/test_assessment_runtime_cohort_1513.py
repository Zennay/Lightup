"""All-or-none lab cohort comparison: no execution, no implicit GO."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from lightup.ai.assessment_runtime_cohort_1513 import compare_lab_cohorts
from lightup.ai.orchestration import RunContext
from lightup.labeval import EvaluationMetrics, EvaluationRecord


def fixture(scenario, version, valid=4):
    run = "run-" + version + "-" + scenario
    return (
        EvaluationRecord("rec-" + run, scenario, run, "lab-fixture",
                         (("planner", "scripted/lab"),),
                         EvaluationMetrics(valid_findings=valid,
                                           coverage_assessed=3,
                                           evidence_quality=0.8,
                                           remediation_quality=0.7,
                                           runtime_seconds=1.0),
                         "2026-10-16T21:00:00+00:00"),
        RunContext.for_lab(run, engagement_id=scenario),
    )


class CohortTests(unittest.TestCase):
    def test_complete_cohort_sorted_and_non_authorizing(self):
        old = (fixture("beta", "old"), fixture("alpha", "old"))
        new = (fixture("alpha", "new", 5), fixture("beta", "new"))
        result = compare_lab_cohorts(old, new)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(tuple(s for s, _ in result.comparisons), ("alpha", "beta"))
        for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, flag), False)

    def test_single_scenario_regression_dominates_improvement(self):
        old = (fixture("a", "old"), fixture("b", "old"))
        new = (fixture("a", "new", 20), fixture("b", "new", 3))
        result = compare_lab_cohorts(old, new)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.regressed_scenarios, ("b",))
        self.assertEqual(result.comparisons[1][1].regressions, ("valid_findings",))

    def test_malformed_or_incomplete_cohort_never_reports_partial_results(self):
        old = (fixture("a", "old"), fixture("b", "old"))
        valid = (fixture("a", "new"), fixture("b", "new"))
        malformed = [
            (), valid[:1], valid + (fixture("c", "new"),),
            (valid[0], valid[0]),
            (fixture("A", "new"), valid[1]),
            list(valid), ([valid[0][0], valid[0][1]], valid[1]),
            tuple(fixture(f"s{i}", "new") for i in range(65)),
        ]
        for candidate in malformed:
            with self.subTest(value=repr(candidate)[:60]):
                result = compare_lab_cohorts(old, candidate)
                self.assertEqual((result.status, result.comparisons, result.regressed_scenarios),
                                 ("HOLD", (), ()))

    def test_corrupt_middle_entry_is_atomic_hold(self):
        old = tuple(fixture(s, "old") for s in ("a", "b", "c"))
        new = list(fixture(s, "new") for s in ("a", "b", "c"))
        r, ctx = new[1]
        new[1] = (replace(r, metrics=replace(r.metrics, tool_calls=True)), ctx)
        result = compare_lab_cohorts(old, tuple(new))
        self.assertEqual((result.status, result.comparisons), ("HOLD", ()))

    def test_exact_boundary_and_no_handler_side_effects(self):
        old = (fixture("a", "old"),)
        new = (fixture("a", "new"),)
        snapshot = deepcopy((old, new))
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            result = compare_lab_cohorts(old, new)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual((old, new), snapshot)
        self.assertEqual(compare_lab_cohorts((), ()).status, "HOLD")
        self.assertEqual(compare_lab_cohorts(list(old), new).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
