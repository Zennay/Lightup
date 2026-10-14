from __future__ import annotations

import unittest

from lightup.ai.gateway import (
    ModelGateway,
    ModelRequest,
    ModelResponse,
    ModelRole,
    ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


LABRUN_RESULT = {
    "target": "http://127.0.0.1:18080/",
    "evidence_id": "ev-verdict",
    "findings": [
        {
            "finding": "Missing Content-Security-Policy header",
            "severity": "medium",
            "impact": "Unrestricted script execution",
            "fix": "Serve a restrictive CSP",
        }
    ],
    "coverage": {"counts": {"assessed": 1, "unknown": 30}},
}


class RecordingScriptedProvider(ScriptedProvider):
    def __init__(self, verifier_text: str) -> None:
        super().__init__(
            "scripted-verdict",
            {
                ModelRole.VERIFIER: [verifier_text],
                ModelRole.REMEDIATION_ADVISOR: [
                    "Apply the defensive control, then verify the header."
                ],
                ModelRole.REPORT_SYNTHESIZER: ["Client-facing summary."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline(provider: RecordingScriptedProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway)


class PipelineVerifierVerdictContractTest(unittest.TestCase):
    def test_allowed_verdict_tokens_are_preserved_byte_for_byte(self):
        verdicts = (
            "CONFIRMED evidence matches",
            "UNCERTAIN evidence is incomplete",
            "REJECTED finding is unsupported",
            "CONFIRMED",
            "CONFIRMED evidence matches\nsecond-line rationale",
        )
        for verdict in verdicts:
            with self.subTest(verdict=verdict):
                provider = RecordingScriptedProvider(verdict)

                result = _pipeline(provider).review(LABRUN_RESULT)

                self.assertEqual(result.findings[0].verdict, verdict)
                self.assertEqual(
                    tuple(request.role for request in provider.requests),
                    (
                        ModelRole.VERIFIER,
                        ModelRole.REMEDIATION_ADVISOR,
                        ModelRole.REPORT_SYNTHESIZER,
                    ),
                )

    def test_invalid_verdict_fails_before_remediation_or_reporting(self):
        invalid_verdicts = (
            "",
            " ",
            "confirmed evidence matches",
            "APPROVED evidence matches",
            "CONFIRMEDLY evidence matches",
            "CONFIRMED:evidence matches",
            "Reason first\nCONFIRMED evidence matches",
            "\nCONFIRMED evidence matches",
            " CONFIRMED evidence matches",
        )
        for verdict in invalid_verdicts:
            with self.subTest(verdict=repr(verdict)):
                provider = RecordingScriptedProvider(verdict)

                with self.assertRaisesRegex(
                    ValueError,
                    "verifier verdict must start with",
                ):
                    _pipeline(provider).review(LABRUN_RESULT)

                self.assertEqual(
                    tuple(request.role for request in provider.requests),
                    (ModelRole.VERIFIER,),
                )


if __name__ == "__main__":
    unittest.main()
