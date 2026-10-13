"""Regression tests for issue #847: preserve concrete target attribution.

Offline scripted model gateway only; no network, scans, or authorization changes.
"""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class CapturingProvider(ScriptedProvider):
    def __init__(self, count: int):
        super().__init__("attribution-847", {
            ModelRole.VERIFIER: [f"CONFIRMED evidence {i}" for i in range(count)],
            ModelRole.REMEDIATION_ADVISOR: [f"Fix and retest {i}" for i in range(count)],
            ModelRole.REPORT_SYNTHESIZER: ["Offline report"],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def review(run: dict):
    provider = CapturingProvider(len(run["findings"]))
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline")
    return AssessmentReviewPipeline(gateway).review(run), provider


def finding(title: str, target: str | None) -> dict:
    row = {
        "finding": title, "severity": "medium", "impact": "Synthetic impact",
        "fix": "Synthetic remediation", "evidence_ids": ["lab:1"],
        "evidence_summary": "Synthetic evidence only",
    }
    if target is not None:
        row["target"] = target
    return row


def payloads(provider: CapturingProvider, role: ModelRole) -> list[dict]:
    return [
        json.loads(next(msg.content for msg in request.messages if msg.role == "user"))
        for request in provider.requests if request.role is role
    ]


class TargetAttributionContract847(unittest.TestCase):
    def test_concrete_targets_preserved_in_all_roles_and_serialization(self):
        targets = ["asset-one.invalid/api", "asset-two.invalid/admin", "asset-three.invalid/🔒"]
        run = {"target": "aggregate", "findings": [finding("same-title", t) for t in targets]}
        before = deepcopy(run)
        result, provider = review(run)
        self.assertEqual([x.target for x in result.findings], targets)
        self.assertEqual([x["target"] for x in result.to_dict()["findings"]], targets)
        for role in AssessmentReviewPipeline.ROLES:
            self.assertEqual([x["target"] for x in payloads(provider, role)][0:len(targets)]
                             if role != ModelRole.REPORT_SYNTHESIZER else
                             [x["target"] for x in payloads(provider, role)[0]["findings"]],
                             targets)
        self.assertEqual(run, before)

    def test_duplicate_titles_do_not_collapse_assets(self):
        run = {"target": "aggregate", "findings": [
            finding("duplicate", "first.invalid"), finding("duplicate", "second.invalid")]}
        result, provider = review(run)
        self.assertEqual([x["finding"] for x in result.to_dict()["findings"]],
                         ["duplicate", "duplicate"])
        self.assertEqual([x["target"] for x in payloads(provider, ModelRole.REPORT_SYNTHESIZER)[0]["findings"]],
                         ["first.invalid", "second.invalid"])
        self.assertEqual([x.remediation_advice for x in result.findings],
                         ["Fix and retest 0", "Fix and retest 1"])

    def test_missing_local_target_uses_existing_multitarget_fallback(self):
        run = {"targets": ["a.invalid", "b.invalid"], "findings": [
            finding("no-local", None), finding("local", "b.invalid/concrete")]}
        result, provider = review(run)
        expected = ["a.invalid, b.invalid", "b.invalid/concrete"]
        self.assertEqual([x.target for x in result.findings], expected)
        self.assertEqual([x["target"] for x in result.to_dict()["findings"]], expected)
        for role in (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR):
            self.assertEqual([x["target"] for x in payloads(provider, role)], expected)

    def test_unicode_target_preserves_other_fields(self):
        target = "lab.invalid/naïef/🔒?item=a%2Fb"
        run = {"target": "aggregate", "coverage": {"counts": {"unknown": 1}},
               "findings": [finding("unicode", target)]}
        before = deepcopy(run)
        result, provider = review(run)
        row = result.to_dict()["findings"][0]
        self.assertEqual(row["target"], target)
        self.assertEqual(row["finding"], "unicode")
        self.assertEqual(row["severity"], "medium")
        self.assertEqual(row["verdict"], "CONFIRMED evidence 0")
        self.assertEqual(row["remediation_advice"], "Fix and retest 0")
        self.assertEqual(payloads(provider, ModelRole.REPORT_SYNTHESIZER)[0]["findings"][0]["target"], target)
        self.assertEqual(run, before)

    def test_single_target_unchanged(self):
        run = {"target": "single.invalid", "findings": [finding("one", None)]}
        result, provider = review(run)
        self.assertEqual(result.findings[0].target, "single.invalid")
        self.assertEqual(payloads(provider, ModelRole.REPORT_SYNTHESIZER)[0]["findings"][0]["target"],
                         "single.invalid")


if __name__ == "__main__":
    unittest.main()
