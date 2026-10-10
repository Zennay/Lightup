"""Opt-in output-readiness tests, without external providers or targets."""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.review_advice_guard import review_with_batch_and_advice_guards


class RecordingProvider(ScriptedProvider):
    def __init__(self, advice: object = "  Lab-only remediation guidance  "):
        super().__init__("scripted-advisor-guard", {
            ModelRole.VERIFIER: ["UNCERTAIN synthetic test data"],
            ModelRole.REMEDIATION_ADVISOR: [advice],
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic report only."],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline(provider):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "test-only-model")
    return AssessmentReviewPipeline(gateway)


def _data() -> dict:
    return {"target": "http://127.0.0.1:18080/", "findings": [{
        "finding": "Synthetic header finding",
        "severity": "low",
        "impact": "Synthetic statement only",
        "fix": "Apply local test policy",
        "evidence_summary": "Two simulated signals.",
        "evidence_ids": ["proof:1", "proof:2"],
    }], "coverage": {"counts": {"assessed": 1}}}


class ReviewAdviceGuardTest(unittest.TestCase):
    def test_positive_advice_passes_without_trimming_or_extra_requests(self):
        provider = RecordingProvider()
        source = _data()
        original = copy.deepcopy(source)
        result = review_with_batch_and_advice_guards(_pipeline(provider), source)
        self.assertEqual(source, original)
        self.assertEqual(result.findings[0].remediation_advice,
                         "  Lab-only remediation guidance  ")
        self.assertEqual([r.role for r in provider.requests], [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
            ModelRole.REPORT_SYNTHESIZER,
        ])

    def test_empty_and_whitespace_advice_never_reaches_report(self):
        for invalid in ("", " \n\t ", "\u2003\u2003"):
            with self.subTest(value=repr(invalid)):
                provider = RecordingProvider(invalid)
                source = _data()
                original = copy.deepcopy(source)
                with self.assertRaisesRegex(ValueError, "invalid bounded advice"):
                    review_with_batch_and_advice_guards(_pipeline(provider), source)
                self.assertEqual([r.role for r in provider.requests], [
                    ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                ])
                self.assertEqual(source, original)

    def test_noncanonical_and_overlarge_advice_never_reaches_report(self):
        class Spoof(str):
            def __str__(self):
                raise AssertionError("must not invoke untrusted str")
        for invalid in (None, 7, b"bytes", Spoof("text"), "x" * 8193):
            with self.subTest(type=type(invalid).__name__):
                provider = RecordingProvider(invalid)
                source = _data()
                with self.assertRaises(ValueError):
                    review_with_batch_and_advice_guards(_pipeline(provider), source)
                self.assertEqual([r.role for r in provider.requests], [
                    ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                ])

    def test_bad_second_finding_emits_no_model_request(self):
        provider = RecordingProvider()
        source = _data()
        second = copy.deepcopy(source["findings"][0])
        second["fix"] = " "
        source["findings"].append(second)
        original = copy.deepcopy(source)
        with self.assertRaises(ValueError):
            review_with_batch_and_advice_guards(_pipeline(provider), source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, original)

    def test_missing_evidence_and_duplicate_evidence_prevent_all_models(self):
        for refs in ([], ["proof:1", "proof:1"]):
            with self.subTest(refs=refs):
                provider = RecordingProvider()
                source = _data()
                source["findings"][0]["evidence_ids"] = refs
                with self.assertRaises(ValueError):
                    review_with_batch_and_advice_guards(_pipeline(provider), source)
                self.assertEqual(provider.requests, [])

    def test_advisor_reply_with_mismatched_model_identity_denied(self):
        class SpoofModelProvider(RecordingProvider):
            def complete(self, request):
                real = super().complete(request)
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    return ModelResponse(
                        provider_id=self.provider_id,
                        model_id="different-model",
                        role=real.role, content=real.content,
                    )
                return real

        provider = SpoofModelProvider()
        with self.assertRaises(ValueError):
            review_with_batch_and_advice_guards(_pipeline(provider), _data())
        self.assertEqual(len(provider.requests), 2)

    def test_advisor_reply_with_wrong_role_denied(self):
        class SpoofRoleProvider(RecordingProvider):
            def complete(self, request):
                real = super().complete(request)
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    return ModelResponse(
                        provider_id=self.provider_id, model_id=real.model_id,
                        role=ModelRole.VERIFIER, content=real.content,
                    )
                return real

        provider = SpoofRoleProvider()
        with self.assertRaises(ValueError):
            review_with_batch_and_advice_guards(_pipeline(provider), _data())
        self.assertEqual(len(provider.requests), 2)

    def test_invalid_source_summary_cannot_trigger_verifier(self):
        provider = RecordingProvider()
        source = _data()
        source["findings"][0]["evidence_summary"] = ""
        with self.assertRaises(ValueError):
            review_with_batch_and_advice_guards(_pipeline(provider), source)
        self.assertEqual(provider.requests, [])

    def test_bad_pipeline_cannot_be_used_as_delegate(self):
        with self.assertRaises(ValueError):
            review_with_batch_and_advice_guards(object(), _data())


if __name__ == "__main__":
    unittest.main()
