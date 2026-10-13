"""Offline report-context acceptance for #847 (synthetic data only).

Tests do not contact targets, execute tools, or alter authorization.
"""
from __future__ import annotations

import unittest

from lightup.ai.gateway import ModelRole
from tests.test_review_target_attribution_extended_847 import (
    _finding, _requests, _run,
)


class TargetAttributionReportContract847(unittest.TestCase):
    def test_report_preserves_coverage_order_and_model_bindings(self):
        findings = [
            _finding(0, "alpha.invalid/api"),
            _finding(1, "beta.invalid/admin"),
        ]
        result, provider, run, before = _run(
            findings, target=None, targets=["alpha.invalid", "beta.invalid"],
            coverage={"counts": {"assessed": 2, "unknown": 3}},
        )
        report = _requests(provider, ModelRole.REPORT_SYNTHESIZER)[0]
        self.assertEqual(report["target"], "alpha.invalid, beta.invalid")
        self.assertEqual(report["coverage_counts"], {"assessed": 2, "unknown": 3})
        self.assertEqual([f["finding"] for f in report["findings"]],
                         ["same-title-0", "same-title-1"])
        self.assertEqual([f["target"] for f in report["findings"]],
                         ["alpha.invalid/api", "beta.invalid/admin"])
        self.assertEqual(result.to_dict()["model_bindings"], {
            role.value: "attribution-847-stress/offline"
            for role in (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                         ModelRole.REPORT_SYNTHESIZER)
        })
        self.assertEqual(run, before)

    def test_report_retains_severity_verdict_and_advice_per_concrete_target(self):
        result, provider, run, before = _run([
            _finding(0, "one.invalid"), _finding(1, "two.invalid")
        ])
        report = _requests(provider, ModelRole.REPORT_SYNTHESIZER)[0]
        self.assertEqual(report["findings"], [
            {"finding": "same-title-0", "severity": "medium", "target": "one.invalid",
             "verdict": "CONFIRMED evidence 0", "remediation_advice": "Synthetic fix 0"},
            {"finding": "same-title-1", "severity": "medium", "target": "two.invalid",
             "verdict": "CONFIRMED evidence 1", "remediation_advice": "Synthetic fix 1"},
        ])
        self.assertEqual([f.target for f in result.findings], ["one.invalid", "two.invalid"])
        self.assertEqual(run, before)


if __name__ == "__main__":
    unittest.main()
