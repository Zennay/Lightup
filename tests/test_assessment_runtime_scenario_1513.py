"""Offline ground-truth/asset drift guard for assessment-runtime (#1513)."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import subprocess
import socket
import unittest
from unittest.mock import patch

from lightup.ai.assessment_runtime_scenario_1513 import (
    compare_ground_truthed_lab_evaluations,
)
from lightup.labeval import (
    EvaluationMetrics, ExpectedFinding, LabEvaluationHarness, LabScenario,
)


TRUTH = (ExpectedFinding("f1", "Lab planted header", "web-baseline", "medium"),)


def scenario(target="127.0.0.1", findings=TRUTH, name="synthetic lab"):
    return LabScenario("same-id", name, targets=(target,), expected_findings=findings)


def records(lab):
    harness = LabEvaluationHarness()
    context = harness.start_run(lab)
    record = harness.record(
        lab, context,
        EvaluationMetrics(valid_findings=1, coverage_assessed=1,
                          evidence_quality=0.7, reproducibility=0.8),
    )
    return record, context


class GroundTruthScenarioTests(unittest.TestCase):
    def test_exact_scored_scenario_gives_review_only_and_never_authority(self):
        lab1, lab2 = scenario(), scenario()
        a, ca = records(lab1)
        b, cb = records(lab2)
        result = compare_ground_truthed_lab_evaluations(lab1, lab2, a, b, ca, cb)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(len(result.changes), 15)
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(result, field), False)

    def test_changed_target_or_ground_truth_is_generic_hold(self):
        original = scenario()
        a, ca = records(original)
        variants = (
            scenario(target="127.0.0.2"),
            scenario(findings=(ExpectedFinding("f2", "Different finding",
                                               "web-baseline", "medium"),)),
            scenario(name="renamed lab"),
            scenario(findings=()),
            scenario(findings=None),
            replace(scenario(), description="another fixture"),
        )
        for variant in variants:
            with self.subTest(name=variant.name, targets=variant.targets):
                b, cb = records(variant)
                result = compare_ground_truthed_lab_evaluations(
                    original, variant, a, b, ca, cb,
                )
                self.assertEqual((result.status, result.changes, result.regressions),
                                 ("HOLD", (), ()))

    def test_duplicate_and_unscored_ground_truth_never_pass(self):
        for findings in (None, (TRUTH[0], TRUTH[0])):
            old, new = scenario(findings=findings), scenario(findings=findings)
            a, ca = records(old)
            b, cb = records(new)
            result = compare_ground_truthed_lab_evaluations(old, new, a, b, ca, cb)
            self.assertEqual((result.status, result.changes), ("HOLD", ()))

    def test_unscored_corrupt_and_foreign_records_fail_closed(self):
        original = scenario()
        a, ca = records(original)
        b, cb = records(original)
        tampered = deepcopy(original)
        object.__setattr__(tampered, "targets", ("127.0.0.1", 123))
        for mutated in (
            (original, original, a, replace(b, scenario_id="different"), ca, cb),
            (original, original, a, b, ca, replace(cb, client_id="foreign-client")),
            (original, object(), a, b, ca, cb),
            (original, tampered, a, b, ca, cb),
        ):
            result = compare_ground_truthed_lab_evaluations(*mutated)
            self.assertEqual((result.status, result.changes), ("HOLD", ()))

    def test_equal_forged_public_lab_assets_never_receive_review_only(self):
        # Two identically forged frozen snapshots previously passed equality.
        original = scenario()
        a, ca = records(original)
        b, cb = records(original)
        for address in ('8.8.8.8', '2001:4860:4860::8888',
                        '0.0.0.0', '224.0.0.1', 'example.test'):
            with self.subTest(address=address):
                old, new = deepcopy(original), deepcopy(original)
                for forged in (old, new):
                    object.__setattr__(forged, 'targets', (address,))
                    object.__setattr__(forged, 'endpoints', (address,))
                with patch.object(socket, 'socket', side_effect=AssertionError('network')):
                    result = compare_ground_truthed_lab_evaluations(
                        old, new, a, b, ca, cb,
                    )
                self.assertEqual((result.status, result.changes, result.regressions),
                                 ('HOLD', (), ()))
                self.assertIs(result.release_allowed, False)

    def test_forged_original_endpoint_binding_is_denied(self):
        original = scenario()
        a, ca = records(original)
        b, cb = records(original)
        for endpoint in ('8.8.8.8', 'http://8.8.8.8',
                         'http://127.0.0.1@other.example',
                         'http://[::1', 'localhost'):
            with self.subTest(endpoint=endpoint):
                old, new = deepcopy(original), deepcopy(original)
                for forged in (old, new):
                    object.__setattr__(forged, 'endpoints', (endpoint,))
                result = compare_ground_truthed_lab_evaluations(
                    old, new, a, b, ca, cb,
                )
                self.assertEqual((result.status, result.changes), ('HOLD', ()))

    def test_original_url_loopback_and_private_lab_endpoints_remain_review_only(self):
        for target in ('http://127.0.0.1:8080/fixture',
                       'http://localhost:8080/fixture',
                       '10.1.2.3', '192.168.1.5'):
            with self.subTest(target=target):
                old, new = scenario(target=target), scenario(target=target)
                a, ca = records(old)
                b, cb = records(new)
                result = compare_ground_truthed_lab_evaluations(old, new, a, b, ca, cb)
                self.assertEqual(result.status, 'REVIEW_ONLY')
                self.assertIs(result.authorized, False)

    def test_pure_scenario_comparison_no_io_or_mutation(self):
        old, new = scenario(), scenario()
        a, ca = records(old)
        b, cb = records(new)
        items = old, new, a, b, ca, cb
        snapshot = deepcopy(items)
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            result = compare_ground_truthed_lab_evaluations(*items)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(items, snapshot)


if __name__ == "__main__":
    unittest.main()
