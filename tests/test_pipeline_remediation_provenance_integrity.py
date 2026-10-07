from __future__ import annotations

import unittest

from lightup.ai.gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelRole,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


LABRUN_RESULT = {
    "target": "http://127.0.0.1:18080/",
    "evidence_id": "ev-provenance",
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


class _StringSubclass(str):
    pass


class OverrideProvider(ModelProvider):
    def __init__(
        self,
        target_role: ModelRole | None = None,
        *,
        response_role: ModelRole | None = None,
        response_model_id: str | None = None,
        response_content: object | None = None,
    ) -> None:
        self.target_role = target_role
        self.response_role = response_role
        self.response_model_id = response_model_id
        self.response_content = response_content
        self.requests: list[ModelRequest] = []

    @property
    def provider_id(self) -> str:
        return "override"

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        selected = request.role is self.target_role
        content = {
            ModelRole.VERIFIER: "CONFIRMED evidence matches",
            ModelRole.REMEDIATION_ADVISOR: "Apply the defensive control and retest.",
            ModelRole.REPORT_SYNTHESIZER: "Client-facing summary.",
        }[request.role]
        if selected and self.response_content is not None:
            content = self.response_content  # type: ignore[assignment]
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=(
                self.response_model_id
                if selected and self.response_model_id is not None
                else request.model_id
            ),
            role=(
                self.response_role
                if selected and self.response_role is not None
                else request.role
            ),
            content=content,  # type: ignore[arg-type]
        )


def _pipeline(provider: OverrideProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "lab-model")
    return AssessmentReviewPipeline(gateway)


class PipelineRemediationProvenanceIntegrityTest(unittest.TestCase):
    def test_canonical_role_model_and_text_provenance_remains_green(self):
        provider = OverrideProvider()

        result = _pipeline(provider).review(LABRUN_RESULT)

        self.assertEqual(result.findings[0].verdict, "CONFIRMED evidence matches")
        self.assertEqual(
            result.findings[0].remediation_advice,
            "Apply the defensive control and retest.",
        )
        self.assertEqual(result.report, "Client-facing summary.")
        self.assertEqual(
            dict(result.model_bindings),
            {
                "verifier": "override/lab-model",
                "remediation_advisor": "override/lab-model",
                "report_synthesizer": "override/lab-model",
            },
        )

    def test_wrong_verifier_role_fails_before_remediation_or_report(self):
        provider = OverrideProvider(
            ModelRole.VERIFIER,
            response_role=ModelRole.SECURITY_ANALYST,
        )

        with self.assertRaisesRegex(GatewayConfigurationError, "wrong model role"):
            _pipeline(provider).review(LABRUN_RESULT)

        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (ModelRole.VERIFIER,),
        )

    def test_wrong_or_polymorphic_remediation_model_identity_fails_closed(self):
        for model_id in ("other-model", _StringSubclass("lab-model")):
            with self.subTest(model_id=model_id):
                provider = OverrideProvider(
                    ModelRole.REMEDIATION_ADVISOR,
                    response_model_id=model_id,
                )

                with self.assertRaisesRegex(
                    GatewayConfigurationError,
                    "wrong model identity",
                ):
                    _pipeline(provider).review(LABRUN_RESULT)

                self.assertEqual(
                    tuple(request.role for request in provider.requests),
                    (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR),
                )

    def test_invalid_report_text_fails_before_review_result_is_returned(self):
        for content in ("", "   ", _StringSubclass("Client-facing summary.")):
            with self.subTest(content=repr(content)):
                provider = OverrideProvider(
                    ModelRole.REPORT_SYNTHESIZER,
                    response_content=content,
                )

                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    _pipeline(provider).review(LABRUN_RESULT)

                self.assertEqual(
                    tuple(request.role for request in provider.requests),
                    (
                        ModelRole.VERIFIER,
                        ModelRole.REMEDIATION_ADVISOR,
                        ModelRole.REPORT_SYNTHESIZER,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
