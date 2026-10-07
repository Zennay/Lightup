from __future__ import annotations

import copy
import json
import unittest

from lightup.ai.gateway import ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider
from lightup.ai.pipeline import AssessmentReviewPipeline


BASE_RESULT = {
    "target": "http://127.0.0.1:18080/",
    "findings": [
        {
            "finding": "Missing Content-Security-Policy header",
            "severity": "medium",
            "impact": "Unrestricted script execution",
            "fix": "Serve a restrictive CSP",
            "evidence_ids": ["evidence:ev-1"],
            "evidence_summary": "HTTP baseline observed no Content-Security-Policy header.",
        }
    ],
    "coverage": {"counts": {"assessed": 1, "unknown": 30}},
}


class CapturingProvider(ScriptedProvider):
    def __init__(self) -> None:
        super().__init__(
            "capturing",
            {
                ModelRole.VERIFIER: ["CONFIRMED evidence matches"],
                ModelRole.REMEDIATION_ADVISOR: ["Apply CSP and retest."],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline(provider: CapturingProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway)


class PipelineEvidenceSummaryBindingTest(unittest.TestCase):
    def test_verifier_receives_finding_local_evidence_summary_and_references(self):
        provider = CapturingProvider()

        _pipeline(provider).review(copy.deepcopy(BASE_RESULT))

        verifier = provider.requests[0]
        payload = json.loads(
            next(message.content for message in verifier.messages if message.role == "user")
        )
        self.assertEqual(
            payload["evidence_summary"],
            "HTTP baseline observed no Content-Security-Policy header.",
        )
        self.assertEqual(payload["evidence_ids"], ["evidence:ev-1"])
        self.assertNotIn("evidence_payload", payload)

    def test_top_level_baseline_evidence_id_is_a_supported_fallback(self):
        provider = CapturingProvider()
        result = copy.deepcopy(BASE_RESULT)
        result["evidence_id"] = "ev-top-level"
        result["findings"][0].pop("evidence_ids")

        _pipeline(provider).review(result)

        payload = json.loads(
            next(
                message.content
                for message in provider.requests[0].messages
                if message.role == "user"
            )
        )
        self.assertEqual(payload["evidence_ids"], ["ev-top-level"])

    def test_missing_evidence_fails_before_any_model_call(self):
        cases = []

        missing_summary = copy.deepcopy(BASE_RESULT)
        missing_summary["findings"][0].pop("evidence_summary")
        cases.append(missing_summary)

        missing_refs = copy.deepcopy(BASE_RESULT)
        missing_refs["findings"][0].pop("evidence_ids")
        cases.append(missing_refs)

        for result in cases:
            with self.subTest(result=result):
                provider = CapturingProvider()
                with self.assertRaisesRegex(ValueError, "evidence"):
                    _pipeline(provider).review(result)
                self.assertEqual(provider.requests, [])

    def test_evidence_input_bounds_fail_before_any_model_call(self):
        oversized_summary = copy.deepcopy(BASE_RESULT)
        oversized_summary["findings"][0]["evidence_summary"] = "x" * 4097

        too_many_refs = copy.deepcopy(BASE_RESULT)
        too_many_refs["findings"][0]["evidence_ids"] = [
            f"evidence:ev-{index}" for index in range(65)
        ]

        for result in (oversized_summary, too_many_refs):
            with self.subTest(result=result):
                provider = CapturingProvider()
                with self.assertRaisesRegex(ValueError, "bounded"):
                    _pipeline(provider).review(result)
                self.assertEqual(provider.requests, [])


if __name__ == "__main__":
    unittest.main()
