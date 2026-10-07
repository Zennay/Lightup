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


class CapturingAdvisorProvider(ScriptedProvider):
    def __init__(self, verdict: str = "UNCERTAIN evidence needs follow-up") -> None:
        super().__init__(
            "capturing-advisor",
            {
                ModelRole.VERIFIER: [verdict],
                ModelRole.REMEDIATION_ADVISOR: [
                    "Validate the evidence first, then apply and retest CSP."
                ],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _review(provider: CapturingAdvisorProvider):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway).review(
        {
            "target": "http://127.0.0.1:18080/",
            "findings": [
                {
                    "finding": "Missing Content-Security-Policy header",
                    "severity": "medium",
                    "impact": "Unrestricted script execution",
                    "fix": "Serve a restrictive CSP",
                    "target": "http://127.0.0.1:18080/app",
                    "evidence_ids": ["evidence:ev-csp"],
                    "evidence_summary": "HTTP baseline observed no CSP header.",
                }
            ],
            "coverage": {"counts": {"assessed": 1, "unknown": 30}},
        }
    )


class RemediationAdvisorEvidenceContextTest(unittest.TestCase):
    def test_advisor_receives_verified_evidence_context(self):
        provider = CapturingAdvisorProvider()

        review = _review(provider)

        self.assertEqual(
            review.findings[0].remediation_advice,
            "Validate the evidence first, then apply and retest CSP.",
        )
        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ),
        )
        request = provider.requests[1]
        system = next(
            message.content for message in request.messages if message.role == "system"
        )
        self.assertIn("UNCERTAIN", system)
        self.assertIn("REJECTED", system)

        payload = json.loads(
            next(message.content for message in request.messages if message.role == "user")
        )
        self.assertEqual(
            payload,
            {
                "finding": "Missing Content-Security-Policy header",
                "severity": "medium",
                "impact": "Unrestricted script execution",
                "target": "http://127.0.0.1:18080/app",
                "current_fix": "Serve a restrictive CSP",
                "verifier_verdict": "UNCERTAIN evidence needs follow-up",
                "evidence_ids": ["evidence:ev-csp"],
                "evidence_summary": "HTTP baseline observed no CSP header.",
            },
        )
        self.assertNotIn("evidence_payload", payload)

    def test_rejected_verdict_is_forwarded_without_being_relabelled(self):
        provider = CapturingAdvisorProvider("REJECTED evidence does not support finding")

        review = _review(provider)

        request = provider.requests[1]
        payload = json.loads(
            next(message.content for message in request.messages if message.role == "user")
        )
        self.assertEqual(
            payload["verifier_verdict"],
            "REJECTED evidence does not support finding",
        )
        self.assertEqual(
            review.findings[0].verdict,
            "REJECTED evidence does not support finding",
        )


if __name__ == "__main__":
    unittest.main()
