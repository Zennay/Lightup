"""Independent #898 provider-output exact-type boundary diagnostics.

Isolated synthetic ModelGateway/AssessmentReviewPipeline acceptance only;
all RED cases are intentionally expected failures on the unchanged #846 owner.
No network, targets, scans, real remediation, grants, verdict authority or deploy.
"""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class StringSubclass(str):
    pass


class CapturingResponseProvider(ScriptedProvider):
    def __init__(self, advice: object):
        super().__init__(
            "synthetic-output-type",
            {
                ModelRole.VERIFIER: ["CONFIRMED synthetic evidence"],
                ModelRole.REMEDIATION_ADVISOR: [advice],
                ModelRole.REPORT_SYNTHESIZER: ["Summary without authority."],
            },
        )
        self.request_roles: list[ModelRole] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.request_roles.append(request.role)
        return super().complete(request)


def _payload():
    return {
        "target": "lab://offline",
        "findings": [{
            "finding": "Synthetic finding",
            "severity": "low",
            "impact": "Synthetic impact",
            "fix": "Document a mitigation and review it.",
            "target": "lab://offline",
            "evidence_ids": ["evidence:synthetic"],
            "evidence_summary": "A non-sensitive synthetic observation.",
        }],
        "coverage": {"counts": {"assessed": 1, "unknown": 1}},
    }


def _review(provider, result):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "fixture-only")
    return AssessmentReviewPipeline(gateway).review(result)


class RemediationAdviceTypeIntegrityExpectedRed(unittest.TestCase):
    def test_exact_builtin_unicode_text_remains_accepted(self):
        advice = "Bespreek de wijziging; bevestig met een nieuwe test 🔐"
        result = _payload()
        original = copy.deepcopy(result)
        provider = CapturingResponseProvider(advice)
        review = _review(provider, result)
        self.assertEqual(review.findings[0].remediation_advice, advice)
        self.assertEqual(result, original)
        self.assertEqual(
            provider.request_roles,
            [
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ],
        )

    def test_normal_text_does_not_change_caller_input(self):
        result = _payload()
        original = copy.deepcopy(result)
        provider = CapturingResponseProvider("Apply then verify.")
        _review(provider, result)
        self.assertEqual(result, original)

    @unittest.expectedFailure
    def test_empty_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid("")

    @unittest.expectedFailure
    def test_whitespace_only_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid("  \t\n ")

    @unittest.expectedFailure
    def test_unicode_whitespace_only_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid(" \u00a0\u2003 ")

    @unittest.expectedFailure
    def test_none_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid(None)

    @unittest.expectedFailure
    def test_bytes_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid(b"untrusted bytes")

    @unittest.expectedFailure
    def test_integer_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid(42)

    @unittest.expectedFailure
    def test_str_subclass_advice_must_refuse_before_report_synthesizer(self):
        self._assert_invalid(StringSubclass("apparently valid"))

    def _assert_invalid(self, advice):
        result = _payload()
        original = copy.deepcopy(result)
        provider = CapturingResponseProvider(advice)
        with self.assertRaisesRegex(ValueError, "remediation.*(text|advice|non-empty)"):
            _review(provider, result)
        self.assertEqual(result, original)
        self.assertEqual(
            provider.request_roles,
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
            "invalid provider response must not reach report synthesizer",
        )


if __name__ == "__main__":
    unittest.main()
