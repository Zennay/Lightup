"""Issue #898: expected-RED multi-finding advisor-output integrity tests.

Dedicated tests-only child of source-owner PR #846. No target or network calls.
These are intentionally RED until canonical source-owner validation is added.
"""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class BatchProvider(ScriptedProvider):
    def __init__(self, advice: list[str]) -> None:
        super().__init__("advisor-batch-w26", {
            ModelRole.VERIFIER: ["CONFIRMED synthetic evidence"] * len(advice),
            ModelRole.REMEDIATION_ADVISOR: advice,
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic report."],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _input() -> dict:
    findings = []
    for label in ("A", "B"):
        findings.append({
            "finding": f"Synthetic missing header {label}",
            "severity": "low",
            "impact": f"Synthetic impact {label}",
            "fix": f"Add header {label}",
            "target": f"http://127.0.0.1:18080/{label.lower()}",
            "evidence_ids": [f"evidence:synthetic-{label.lower()}"],
            "evidence_summary": f"Synthetic local header {label} observation.",
        })
    return {
        "target": "http://127.0.0.1:18080/",
        "findings": findings,
        "coverage": {"counts": {"assessed": 2, "unknown": 5}},
    }


def _review(provider: BatchProvider, data: dict):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway).review(data)


class AdvisorBatchAtomicityW26Test(unittest.TestCase):
    def test_valid_two_findings_preserve_order_and_verbatim_text(self):
        source = _input()
        before = copy.deepcopy(source)
        advice = [" Apply A then retest. ", "Apply B; verify again."]
        provider = BatchProvider(advice)
        result = _review(provider, source)
        self.assertEqual([f.remediation_advice for f in result.findings], advice)
        self.assertEqual(result.report, "Synthetic report.")
        self.assertEqual(source, before)
        self.assertEqual([r.role for r in provider.requests], [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
            ModelRole.REPORT_SYNTHESIZER,
        ])

    def test_later_blank_advice_fails_before_any_report(self):
        for invalid in ("", " \t\n ", "\u2003\u2003"):
            with self.subTest(invalid=repr(invalid)):
                source = _input()
                before = copy.deepcopy(source)
                provider = BatchProvider(["Apply A then retest.", invalid])
                with self.assertRaisesRegex(
                    ValueError, "remediation.*non-empty|non-empty.*remediation"
                ):
                    _review(provider, source)
                self.assertEqual(source, before)
                self.assertEqual([r.role for r in provider.requests], [
                    ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                    ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                ])

    def test_first_blank_advice_fails_before_second_finding(self):
        source = _input()
        before = copy.deepcopy(source)
        provider = BatchProvider(["\u2003", "Apply B then retest."])
        with self.assertRaisesRegex(
            ValueError, "remediation.*non-empty|non-empty.*remediation"
        ):
            _review(provider, source)
        self.assertEqual(source, before)
        self.assertEqual([r.role for r in provider.requests], [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
        ])


if __name__ == "__main__":
    unittest.main()
