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
    def __init__(self) -> None:
        super().__init__(
            "capturing-report",
            {
                ModelRole.VERIFIER: [
                    "CONFIRMED first evidence matches",
                    "UNCERTAIN second evidence needs follow-up",
                ],
                ModelRole.REMEDIATION_ADVISOR: [
                    "Apply CSP before retesting.",
                    "Reduce banner detail and verify again.",
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


class PipelineReportRemediationContextTest(unittest.TestCase):
    def test_report_receives_reviewed_finding_context_in_order(self):
        provider = CapturingReviewProvider()
        result = {
            "target": "http://127.0.0.1:18080/",
            "findings": [
                {
                    "finding": "Missing Content-Security-Policy header",
                    "severity": "medium",
                    "impact": "Unrestricted script execution",
                    "fix": "Serve a restrictive CSP",
                    "evidence_ids": ["evidence:ev-1"],
                    "evidence_summary": "CSP header was absent.",
                },
                {
                    "finding": "Server software banner disclosed",
                    "severity": "info",
                    "impact": "Easier exploit matching",
                    "fix": "Strip the Server header",
                    "evidence_ids": ["evidence:ev-2"],
                    "evidence_summary": "Server header exposed software detail.",
                },
            ],
            "coverage": {"counts": {"assessed": 1, "unknown": 30}},
        }

        review = _pipeline(provider).review(result)

        self.assertEqual(review.report, "Client-facing summary.")
        report_request = provider.requests[-1]
        self.assertIs(report_request.role, ModelRole.REPORT_SYNTHESIZER)
        payload = json.loads(
            next(
                message.content
                for message in report_request.messages
                if message.role == "user"
            )
        )
        self.assertEqual(
            payload["findings"],
            [
                {
                    "finding": "Missing Content-Security-Policy header",
                    "severity": "medium",
                    "target": "http://127.0.0.1:18080/",
                    "verdict": "CONFIRMED first evidence matches",
                    "remediation_advice": "Apply CSP before retesting.",
                },
                {
                    "finding": "Server software banner disclosed",
                    "severity": "info",
                    "target": "http://127.0.0.1:18080/",
                    "verdict": "UNCERTAIN second evidence needs follow-up",
                    "remediation_advice": "Reduce banner detail and verify again.",
                },
            ],
        )
        self.assertEqual(payload["coverage_counts"], {"assessed": 1, "unknown": 30})
        self.assertIsInstance(payload["coverage_counts"], dict)
        self.assertNotIn("evidence_summary", json.dumps(payload))
        self.assertNotIn("evidence_ids", json.dumps(payload))
        self.assertNotIn("evidence_payload", json.dumps(payload))

    def test_empty_findings_keep_structured_coverage_context(self):
        provider = CapturingReviewProvider()

        review = _pipeline(provider).review(
            {
                "target": "http://127.0.0.1/",
                "findings": [],
                "coverage": {"counts": {"assessed": 0, "unknown": 31}},
            }
        )

        self.assertTrue(review.report)
        self.assertEqual(len(provider.requests), 1)
        payload = json.loads(
            next(
                message.content
                for message in provider.requests[0].messages
                if message.role == "user"
            )
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["coverage_counts"], {"assessed": 0, "unknown": 31})


if __name__ == "__main__":
    unittest.main()
