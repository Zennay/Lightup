from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway,
    ModelRequest,
    ModelResponse,
    ModelRole,
    ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class CapturingProvider(ScriptedProvider):
    def __init__(self, remediation_advice: str) -> None:
        super().__init__(
            "remediation-output-integrity",
            {
                ModelRole.VERIFIER: ["CONFIRMED evidence supports the finding"],
                ModelRole.REMEDIATION_ADVISOR: [remediation_advice],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _lab_result() -> dict:
    return {
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


def _review(provider: CapturingProvider, result: dict):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway).review(result)


class RemediationAdvisorOutputIntegrityTest(unittest.TestCase):
    def test_non_empty_advice_remains_canonical(self):
        result = _lab_result()
        provider = CapturingProvider(
            "Validate the evidence, apply the CSP, then repeat the same check."
        )

        review = _review(provider, result)

        self.assertEqual(
            review.findings[0].remediation_advice,
            "Validate the evidence, apply the CSP, then repeat the same check.",
        )
        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ),
        )

    def test_blank_advice_fails_before_report_synthesis(self):
        for advice in ("", "   \t"):
            with self.subTest(advice=repr(advice)):
                result = _lab_result()
                original = copy.deepcopy(result)
                provider = CapturingProvider(advice)

                with self.assertRaisesRegex(
                    ValueError, "remediation.*non-empty|non-empty.*remediation"
                ):
                    _review(provider, result)

                self.assertEqual(result, original)
                self.assertEqual(
                    tuple(request.role for request in provider.requests),
                    (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR),
                )


if __name__ == "__main__":
    unittest.main()
