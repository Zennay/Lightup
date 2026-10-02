from __future__ import annotations

import unittest

from lightup.ai.gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelRole,
    ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline

LABRUN_RESULT = {
    "target": "http://127.0.0.1:18080/",
    "evidence_id": "ev-1",
    "findings": [
        {"finding": "Missing Content-Security-Policy header", "severity": "medium",
         "impact": "Unrestricted script execution", "fix": "Serve a restrictive CSP",
         "retest": "not_tested", "check_id": "missing-content-security-policy"},
        {"finding": "Server software banner disclosed", "severity": "info",
         "impact": "Easier exploit matching", "fix": "Strip the Server header",
         "retest": "not_tested", "check_id": "server-banner-disclosure"},
    ],
    "coverage": {"counts": {"assessed": 1, "unknown": 30}},
}


def _bound_gateway() -> ModelGateway:
    gateway = ModelGateway()
    gateway.register_provider(ScriptedProvider(
        "scripted",
        {ModelRole.VERIFIER: ["CONFIRMED evidence matches", "CONFIRMED banner visible"],
         ModelRole.REPORT_SYNTHESIZER: ["Calm client-facing summary. Coverage largely unknown."]},
    ))
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, "scripted", "lab-model")
    return gateway


class PipelineTest(unittest.TestCase):
    def test_requires_all_roles_bound(self):
        gateway = ModelGateway()
        gateway.register_provider(ScriptedProvider("scripted"))
        gateway.bind_role(ModelRole.VERIFIER, "scripted", "m")
        with self.assertRaises(GatewayConfigurationError):
            AssessmentReviewPipeline(gateway)

    def test_reviews_findings_and_synthesizes_report(self):
        pipeline = AssessmentReviewPipeline(_bound_gateway())
        result = pipeline.review(LABRUN_RESULT)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.findings[0].verdict, "CONFIRMED evidence matches")
        self.assertIn("remediation_advisor", dict(result.model_bindings))
        self.assertIn("Coverage largely unknown", result.report)
        data = result.to_dict()
        self.assertEqual(data["model_bindings"]["verifier"], "scripted/lab-model")
        # The remediation advisor got the current fix as input (echo provider).
        self.assertIn("Serve a restrictive CSP", data["findings"][0]["remediation_advice"])

    def test_empty_findings_still_reports(self):
        pipeline = AssessmentReviewPipeline(_bound_gateway())
        result = pipeline.review({"target": "http://127.0.0.1/", "findings": [],
                                  "coverage": {"counts": {"unknown": 31}}})
        self.assertEqual(result.findings, ())
        self.assertTrue(result.report)


if __name__ == "__main__":
    unittest.main()
