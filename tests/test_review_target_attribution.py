from __future__ import annotations

import json
import unittest

from lightup.ai.gateway import (
    ModelGateway,
    ModelRequest,
    ModelResponse,
    ModelRole,
    ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class CapturingReviewProvider(ScriptedProvider):
    def __init__(self, *, findings: int) -> None:
        super().__init__(
            "capturing-review-targets",
            {
                ModelRole.VERIFIER: [
                    f"CONFIRMED evidence supports finding {index}"
                    for index in range(findings)
                ],
                ModelRole.REMEDIATION_ADVISOR: [
                    f"Remediate finding {index} and retest."
                    for index in range(findings)
                ],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline(provider: CapturingReviewProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway)


def _finding(name: str, target: str | None) -> dict:
    finding = {
        "finding": name,
        "severity": "medium",
        "impact": f"Impact for {name}",
        "fix": f"Fix {name}",
        "evidence_ids": [f"evidence:{name}"],
        "evidence_summary": f"Evidence for {name}",
    }
    if target is not None:
        finding["target"] = target
    return finding


class ReviewTargetAttributionTest(unittest.TestCase):
    def test_multi_target_attribution_survives_review_serialization_and_report(self):
        provider = CapturingReviewProvider(findings=2)

        review = _pipeline(provider).review(
            {
                "targets": [
                    "http://127.0.0.1:18080/",
                    "http://127.0.0.1:18081/",
                ],
                "findings": [
                    _finding("missing-csp", "http://127.0.0.1:18080/app"),
                    _finding("weak-cache", "http://127.0.0.1:18081/api"),
                ],
                "coverage": {"counts": {"assessed": 2, "unknown": 0}},
            }
        )

        expected_targets = (
            "http://127.0.0.1:18080/app",
            "http://127.0.0.1:18081/api",
        )
        self.assertEqual(tuple(f.target for f in review.findings), expected_targets)
        self.assertEqual(
            tuple(item["target"] for item in review.to_dict()["findings"]),
            expected_targets,
        )

        report_request = next(
            request
            for request in provider.requests
            if request.role is ModelRole.REPORT_SYNTHESIZER
        )
        report_payload = json.loads(
            next(
                message.content
                for message in report_request.messages
                if message.role == "user"
            )
        )
        self.assertEqual(
            tuple(item["target"] for item in report_payload["findings"]),
            expected_targets,
        )
        self.assertEqual(
            report_payload["target"],
            "http://127.0.0.1:18080/, http://127.0.0.1:18081/",
        )

    def test_single_target_fallback_is_preserved_without_inference(self):
        provider = CapturingReviewProvider(findings=1)
        target = "http://127.0.0.1:18080/"

        review = _pipeline(provider).review(
            {
                "target": target,
                "findings": [_finding("missing-csp", None)],
                "coverage": {"counts": {"assessed": 1, "unknown": 0}},
            }
        )

        self.assertEqual(review.findings[0].target, target)
        self.assertEqual(review.to_dict()["findings"][0]["target"], target)

        report_request = next(
            request
            for request in provider.requests
            if request.role is ModelRole.REPORT_SYNTHESIZER
        )
        report_payload = json.loads(
            next(
                message.content
                for message in report_request.messages
                if message.role == "user"
            )
        )
        self.assertEqual(report_payload["findings"][0]["target"], target)


if __name__ == "__main__":
    unittest.main()
