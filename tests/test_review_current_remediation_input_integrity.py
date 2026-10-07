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


class StringSubclass(str):
    pass


class CapturingProvider(ScriptedProvider):
    def __init__(self) -> None:
        super().__init__(
            "review-current-remediation-integrity",
            {
                ModelRole.VERIFIER: ["CONFIRMED evidence supports the finding"],
                ModelRole.REMEDIATION_ADVISOR: ["Apply the fix and retest."],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _result(fix: object) -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "findings": [
            {
                "finding": "Missing Content-Security-Policy header",
                "severity": "medium",
                "impact": "Unrestricted script execution",
                "fix": fix,
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


class ReviewCurrentRemediationInputIntegrityTest(unittest.TestCase):
    def test_exact_non_empty_remediation_text_remains_canonical(self):
        result = _result("Serve a restrictive CSP")
        provider = CapturingProvider()

        review = _review(provider, result)

        self.assertEqual(review.findings[0].remediation_advice, "Apply the fix and retest.")
        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ),
        )

    def test_malformed_remediation_text_fails_before_any_model_call(self):
        invalid_values = (
            "",
            "   \t",
            42,
            StringSubclass("Serve a restrictive CSP"),
        )
        for fix in invalid_values:
            with self.subTest(fix=repr(fix)):
                result = _result(fix)
                original = copy.deepcopy(result)
                provider = CapturingProvider()

                with self.assertRaises(ValueError):
                    _review(provider, result)

                self.assertEqual(result, original)
                self.assertEqual(provider.requests, [])


if __name__ == "__main__":
    unittest.main()
