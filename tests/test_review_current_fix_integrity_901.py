"""#901 synthetic remediation-current-fix admission acceptance.

Independent tests-only child of original #846 review-pipeline branch.
Expected failures are unresolved source-owner RED, never compliant green.
No network, targets, actual models, evidence acquisition or remediation.
"""
from __future__ import annotations

import copy
import json
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class StringSubclass(str):
    pass


class CapturingProvider(ScriptedProvider):
    def __init__(self):
        super().__init__("synthetic-901", {
            ModelRole.VERIFIER: ["UNCERTAIN pending independent evidence"] * 3,
            ModelRole.REMEDIATION_ADVISOR: ["Apply a bounded fix then retest."] * 3,
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic client summary."],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline(provider: CapturingProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline-scripted")
    return AssessmentReviewPipeline(gateway)


def _finding(fix: object = "  Apply CSP, then retest.  ") -> dict:
    return {
        "finding": "Synthetic missing CSP",
        "severity": "medium",
        "impact": "Synthetic non-executable impact",
        "target": "asset://offline-only",
        "fix": fix,
        "evidence_summary": "Synthetic local fixture; no scan conducted.",
        "evidence_ids": ["evidence:synthetic-901"],
    }


def _batch(*findings: dict) -> dict:
    return {
        "target": "asset://offline-only",
        "findings": list(findings),
        "coverage": {"counts": {"assessed": 1, "unknown": 4}},
    }


class ReviewCurrentFixInputIntegrityAcceptance(unittest.TestCase):
    def _assert_invalid_no_model_calls(self, candidate: object):
        payload = _batch(_finding(candidate))
        before = copy.deepcopy(payload)
        provider = CapturingProvider()
        with self.assertRaisesRegex(ValueError, r"(?i:remediation|current.fix|fix)"):
            _pipeline(provider).review(payload)
        self.assertEqual(provider.requests, [])
        self.assertEqual(payload, before)

    def test_canonical_fix_keeps_original_exact_text_and_model_order(self):
        original = "  Apply CSP, then retest.  "
        payload = _batch(_finding(original))
        before = copy.deepcopy(payload)
        provider = CapturingProvider()

        result = _pipeline(provider).review(payload)

        self.assertEqual(payload, before)
        self.assertEqual(result.findings[0].remediation_advice, "Apply a bounded fix then retest.")
        self.assertEqual(
            [request.role for request in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR, ModelRole.REPORT_SYNTHESIZER],
        )
        advisor_message = next(
            message.content for message in provider.requests[1].messages
            if message.role == "user"
        )
        advisor_data = json.loads(advisor_message)
        self.assertEqual(advisor_data["current_fix"], original)
        self.assertEqual(advisor_data["evidence_ids"], ["evidence:synthetic-901"])
        self.assertNotIn("evidence_payload", advisor_data)

    def test_canonical_multiple_findings_keep_separate_fix_values(self):
        payload = _batch(_finding("Fix A"), _finding("Fix B"))
        provider = CapturingProvider()
        _pipeline(provider).review(payload)
        self.assertEqual(
            [request.role for request in provider.requests],
            [
                ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ],
        )
        advice = [
            json.loads(next(m.content for m in req.messages if m.role == "user"))["current_fix"]
            for req in provider.requests if req.role is ModelRole.REMEDIATION_ADVISOR
        ]
        self.assertEqual(advice, ["Fix A", "Fix B"])

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_empty_fix_refused_before_verifier(self):
        self._assert_invalid_no_model_calls("")

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_whitespace_only_fix_refused_before_verifier(self):
        self._assert_invalid_no_model_calls(" \t\n ")

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_null_fix_refused_before_verifier(self):
        self._assert_invalid_no_model_calls(None)

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_integer_fix_refused_before_verifier(self):
        self._assert_invalid_no_model_calls(12)

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_list_fix_refused_before_verifier(self):
        self._assert_invalid_no_model_calls(["not", "a", "fix"])

    @unittest.expectedFailure  # original #846 source does not validate fix
    def test_string_subclass_refused_before_verifier(self):
        self._assert_invalid_no_model_calls(StringSubclass("Apply CSP"))

    @unittest.expectedFailure  # full batch preflight is not yet installed
    def test_later_bad_fix_refused_before_any_role_for_entire_batch(self):
        payload = _batch(_finding("Valid fix"), _finding(" "))
        before = copy.deepcopy(payload)
        provider = CapturingProvider()
        with self.assertRaisesRegex(ValueError, r"(?i:remediation|current.fix|fix)"):
            _pipeline(provider).review(payload)
        self.assertEqual(provider.requests, [])
        self.assertEqual(payload, before)


if __name__ == "__main__":
    unittest.main()
