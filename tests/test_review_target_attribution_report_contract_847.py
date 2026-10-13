"""Self-contained offline report-context acceptance for #847.

Synthetic scripted models only: no network, targets, grants or tool execution.
"""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class _CapturingProvider(ScriptedProvider):
    def __init__(self, count: int):
        super().__init__("attribution-847-report", {
            ModelRole.VERIFIER: [f"CONFIRMED evidence {i}" for i in range(count)],
            ModelRole.REMEDIATION_ADVISOR: [f"Synthetic fix {i}" for i in range(count)],
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic report"],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _finding(index: int, target: str) -> dict:
    return {
        "finding": f"same-title-{index}", "severity": "medium",
        "impact": "Synthetic impact", "fix": "Synthetic fix", "target": target,
        "evidence_ids": [f"lab:{index}"], "evidence_summary": "Synthetic evidence",
    }


def _review(findings: list[dict], **extras):
    provider = _CapturingProvider(len(findings))
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline")
    source = {"target": "aggregate", "findings": findings, **extras}
    before = deepcopy(source)
    result = AssessmentReviewPipeline(gateway).review(source)
    reports = [request for request in provider.requests
               if request.role is ModelRole.REPORT_SYNTHESIZER]
    assert len(reports) == 1
    report = json.loads(next(message.content for message in reports[0].messages
                             if message.role == "user"))
    return result, report, source, before


class TargetAttributionReportContract847(unittest.TestCase):
    def test_report_preserves_coverage_order_and_model_bindings(self):
        result, report, source, before = _review(
            [_finding(0, "alpha.invalid/api"), _finding(1, "beta.invalid/admin")],
            target=None, targets=["alpha.invalid", "beta.invalid"],
            coverage={"counts": {"assessed": 2, "unknown": 3}},
        )
        self.assertEqual(report["target"], "alpha.invalid, beta.invalid")
        self.assertEqual(report["coverage_counts"], {"assessed": 2, "unknown": 3})
        self.assertEqual([f["finding"] for f in report["findings"]],
                         ["same-title-0", "same-title-1"])
        self.assertEqual([f["target"] for f in report["findings"]],
                         ["alpha.invalid/api", "beta.invalid/admin"])
        self.assertEqual(result.to_dict()["model_bindings"], {
            role.value: "attribution-847-report/offline"
            for role in AssessmentReviewPipeline.ROLES
        })
        self.assertEqual(source, before)

    def test_report_retains_verdict_and_advice_per_concrete_target(self):
        result, report, source, before = _review([
            _finding(0, "one.invalid"), _finding(1, "two.invalid")
        ])
        self.assertEqual(report["findings"], [
            {"finding": "same-title-0", "severity": "medium", "target": "one.invalid",
             "verdict": "CONFIRMED evidence 0", "remediation_advice": "Synthetic fix 0"},
            {"finding": "same-title-1", "severity": "medium", "target": "two.invalid",
             "verdict": "CONFIRMED evidence 1", "remediation_advice": "Synthetic fix 1"},
        ])
        self.assertEqual([f.target for f in result.findings], ["one.invalid", "two.invalid"])
        self.assertEqual(source, before)


if __name__ == "__main__":
    unittest.main()
