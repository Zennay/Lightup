"""Add-only offline stress contracts for issue #847.

All inputs are synthetic; this module never invokes target/network operations.
"""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from lightup.ai.gateway import ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider
from lightup.ai.pipeline import AssessmentReviewPipeline


class CapturingProvider(ScriptedProvider):
    def __init__(self, count: int):
        super().__init__("attribution-847-stress", {
            ModelRole.VERIFIER: [f"CONFIRMED evidence {i}" for i in range(count)],
            ModelRole.REMEDIATION_ADVISOR: [f"Synthetic fix {i}" for i in range(count)],
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic report"],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _run(findings: list[dict], **extras):
    provider = CapturingProvider(len(findings))
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline")
    source = {"target": "aggregate", "findings": findings, **extras}
    original = deepcopy(source)
    result = AssessmentReviewPipeline(gateway).review(source)
    return result, provider, source, original


def _finding(index: int, target: str) -> dict:
    return {
        "finding": f"same-title-{index % 3}", "severity": "medium",
        "impact": "Synthetic impact", "fix": "Synthetic fix", "target": target,
        "evidence_ids": [f"lab:{index}"], "evidence_summary": "Synthetic evidence",
    }


def _requests(provider: CapturingProvider, role: ModelRole) -> list[dict]:
    return [json.loads(next(message.content for message in request.messages
                            if message.role == "user"))
            for request in provider.requests if request.role is role]


class TargetAttributionExtended847(unittest.TestCase):
    def test_32_findings_preserve_position_and_concrete_target_in_all_roles(self):
        targets = [f"lab-{i % 5}.invalid/asset/{i}/🔒" for i in range(32)]
        result, provider, source, original = _run(
            [_finding(i, target) for i, target in enumerate(targets)])
        self.assertEqual([f.target for f in result.findings], targets)
        self.assertEqual([f["target"] for f in result.to_dict()["findings"]], targets)
        for role in (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR):
            self.assertEqual([p["target"] for p in _requests(provider, role)], targets)
        reports = _requests(provider, ModelRole.REPORT_SYNTHESIZER)
        self.assertEqual(len(reports), 1)
        self.assertEqual([f["target"] for f in reports[0]["findings"]], targets)
        self.assertEqual([f["finding"] for f in reports[0]["findings"]],
                         [f"same-title-{i % 3}" for i in range(32)])
        self.assertEqual(source, original)

    def test_json_control_escapes_remain_data_not_new_report_rows(self):
        target = 'lab.invalid/quote="x"\\n\\\\literal\nline\t\r/☃'
        result, provider, source, original = _run([_finding(0, target)])
        self.assertEqual(result.findings[0].target, target)
        for role in AssessmentReviewPipeline.ROLES:
            data = _requests(provider, role)[0]
            observed = data["findings"][0]["target"] if role is ModelRole.REPORT_SYNTHESIZER else data["target"]
            self.assertEqual(observed, target)
        self.assertEqual(len(_requests(provider, ModelRole.REPORT_SYNTHESIZER)[0]["findings"]), 1)
        self.assertEqual(source, original)

    def test_empty_findings_report_has_no_fabricated_assets_or_verification(self):
        result, provider, source, original = _run([], coverage={"counts": {"unknown": 2}})
        self.assertEqual(result.findings, ())
        self.assertEqual(_requests(provider, ModelRole.VERIFIER), [])
        self.assertEqual(_requests(provider, ModelRole.REMEDIATION_ADVISOR), [])
        report = _requests(provider, ModelRole.REPORT_SYNTHESIZER)
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0]["findings"], [])
        self.assertEqual(report[0]["coverage_counts"], {"unknown": 2})
        self.assertEqual(source, original)


if __name__ == "__main__":
    unittest.main()
