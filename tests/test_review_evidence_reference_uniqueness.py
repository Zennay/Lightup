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
    def __init__(self) -> None:
        super().__init__(
            "review-evidence-uniqueness",
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


def _result(evidence_ids: list[str]) -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "findings": [
            {
                "finding": "Missing Content-Security-Policy header",
                "severity": "medium",
                "impact": "Unrestricted script execution",
                "fix": "Serve a restrictive CSP",
                "target": "http://127.0.0.1:18080/app",
                "evidence_ids": evidence_ids,
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


class ReviewEvidenceReferenceUniquenessTest(unittest.TestCase):
    def test_unique_evidence_references_remain_canonical(self):
        result = _result(["evidence:ev-csp", "evidence:ev-response"])
        provider = CapturingProvider()

        review = _review(provider, result)

        self.assertEqual(len(review.findings), 1)
        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ),
        )

    def test_duplicate_evidence_reference_fails_before_verifier(self):
        result = _result(["evidence:ev-csp", "evidence:ev-csp"])
        original = copy.deepcopy(result)
        provider = CapturingProvider()

        with self.assertRaisesRegex(
            ValueError, "evidence.*duplicate|duplicate.*evidence"
        ):
            _review(provider, result)

        self.assertEqual(result, original)
        self.assertEqual(provider.requests, [])


if __name__ == "__main__":
    unittest.main()
