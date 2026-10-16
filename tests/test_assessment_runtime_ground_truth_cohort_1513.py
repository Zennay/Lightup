"""Offline scored lab cohort acceptance: no targets or handlers."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import socket
import subprocess
import unittest
from unittest.mock import patch

from lightup.ai.assessment_runtime_ground_truth_cohort_1513 import compare_ground_truthed_lab_cohorts
from lightup.labeval import EvaluationMetrics, ExpectedFinding, LabEvaluationHarness, LabScenario


def case(identity, count=1):
    scenario = LabScenario(identity, 'fictional ' + identity, ('127.0.0.1',),
        (ExpectedFinding('f-' + identity, 'planted', 'lab-only', 'low'),))
    harness = LabEvaluationHarness()
    context = harness.start_run(scenario)
    record = harness.record(scenario, context, EvaluationMetrics(
        valid_findings=count, coverage_assessed=2,
        evidence_quality=0.8, reproducibility=0.9))
    return scenario, record, context


class GroundTruthCohortTests(unittest.TestCase):
    def test_sorted_lab_cohort_is_review_only_without_authority_or_io(self):
        before = (case('b'), case('a'))
        after = (case('a'), case('b'))
        snapshot = deepcopy((before, after))
        with patch.object(socket, 'socket', side_effect=AssertionError('socket')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process')):
            result = compare_ground_truthed_lab_cohorts(before, after)
        self.assertEqual(result.status, 'REVIEW_ONLY')
        self.assertEqual(tuple(x[0] for x in result.comparisons), ('a', 'b'))
        self.assertEqual((before, after), snapshot)
        for key in ('authorized', 'consent_verified', 'dispatch_allowed', 'release_allowed'):
            self.assertIs(getattr(result, key), False)

    def test_one_regression_dominates_other_scenario_improvement(self):
        result = compare_ground_truthed_lab_cohorts(
            (case('a', 1), case('b', 1)), (case('a', 2), case('b', 0)))
        self.assertEqual((result.status, result.regressed_scenarios), ('HOLD', ('b',)))
        self.assertEqual(len(result.comparisons), 2)
        self.assertIs(result.release_allowed, False)

    def test_missing_duplicate_corrupted_or_drifted_is_atomic_hold(self):
        baseline = (case('a'), case('b'))
        original = case('a')
        ground_truth_drift = (replace(original[0], expected_findings=()), *original[1:])
        forged = deepcopy(original[0])
        object.__setattr__(forged, 'targets', ('8.8.8.8',))
        object.__setattr__(forged, 'endpoints', ('8.8.8.8',))
        candidates = (
            (), (case('a'),), (case('a'), case('a')),
            (case('a'), case('c')), (ground_truth_drift, case('b')),
            ((forged, *original[1:]), case('b')),
            ((object(), *original[1:]), case('b')),
            ('malformed',),
        )
        for candidate in candidates:
            with self.subTest(candidate=repr(candidate)[:60]):
                result = compare_ground_truthed_lab_cohorts(baseline, candidate)
                self.assertEqual((result.status, result.comparisons, result.regressed_scenarios),
                                 ('HOLD', (), ()))

    def test_64_case_and_exact_tuple_boundaries(self):
        before = tuple(case('case-%02d' % i) for i in range(64))
        after = tuple(case('case-%02d' % i) for i in range(64))
        self.assertEqual(compare_ground_truthed_lab_cohorts(before, after).status, 'REVIEW_ONLY')
        self.assertEqual(compare_ground_truthed_lab_cohorts(before + (case('extra'),), after).status, 'HOLD')
        self.assertEqual(compare_ground_truthed_lab_cohorts(list(before), after).status, 'HOLD')
        self.assertEqual(compare_ground_truthed_lab_cohorts(before, list(after)).status, 'HOLD')


if __name__ == '__main__':
    unittest.main()
