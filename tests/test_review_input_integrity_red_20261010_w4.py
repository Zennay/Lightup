"""RED acceptance for LightUp evidence and remediation review admission.

Issues #899 and #901; source owner remains PR #846.  All fixtures are
synthetic: the scripted provider never contacts a real model or target.
"""
from __future__ import annotations

import copy
import json
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline


class RecordingOfflineProvider(ScriptedProvider):
    def __init__(self):
        super().__init__(
            "offline-evidence-review-integrity",
            {
                ModelRole.VERIFIER: ["UNCERTAIN synthetic fixture"],
                ModelRole.REMEDIATION_ADVISOR: ["Review the remediation offline."],
                ModelRole.REPORT_SYNTHESIZER: ["Synthetic report."],
            },
        )
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _fixture() -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "findings": [{
            "finding": "Missing synthetic header",
            "severity": "medium",
            "impact": "Synthetic impact only",
            "fix": "Apply a restrictive test-only policy",
            "evidence_ids": ["evidence:first", "evidence:second"],
            "evidence_summary": "Two simulated observations in a disposable lab.",
        }],
        "coverage": {"counts": {"assessed": 1, "unknown": 1}},
    }


def _pipeline(provider: RecordingOfflineProvider) -> AssessmentReviewPipeline:
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline-model")
    return AssessmentReviewPipeline(gateway)


def _user_payload(request: ModelRequest) -> dict:
    return json.loads(next(
        m.content for m in request.messages if m.role == "user"
    ))


class ReviewEvidenceReferenceIntegrityTest(unittest.TestCase):
    """#899: no duplicate observation may masquerade as two references."""

    def test_unique_evidence_refs_reach_verifier_then_advisor_in_order(self):
        source = _fixture()
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        result = _pipeline(provider).review(source)

        self.assertEqual(source, untouched)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(
            tuple(request.role for request in provider.requests),
            (
                ModelRole.VERIFIER,
                ModelRole.REMEDIATION_ADVISOR,
                ModelRole.REPORT_SYNTHESIZER,
            ),
        )
        for request in provider.requests[:2]:
            self.assertEqual(
                _user_payload(request)["evidence_ids"],
                ["evidence:first", "evidence:second"],
            )

    @unittest.expectedFailure  # RED until source owner enforces #899
    def test_duplicate_evidence_refs_reject_without_any_model_request(self):
        source = _fixture()
        source["findings"][0]["evidence_ids"] = [
            "evidence:first", "evidence:second", "evidence:first"
        ]
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        with self.assertRaises(ValueError):
            _pipeline(provider).review(source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, untouched)

    def test_invalid_reference_shape_is_already_rejected_pre_model(self):
        source = _fixture()
        source["findings"][0]["evidence_ids"] = ("evidence:first",)
        provider = RecordingOfflineProvider()
        with self.assertRaises(ValueError):
            _pipeline(provider).review(source)
        self.assertEqual(provider.requests, [])


    @unittest.expectedFailure  # RED: whole-batch preflight must precede model I/O
    def test_duplicate_in_second_finding_does_not_emit_first_finding(self):
        source = _fixture()
        second = copy.deepcopy(source["findings"][0])
        second["finding"] = "Second synthetic observation"
        second["evidence_ids"] = ["evidence:repeat", "evidence:repeat"]
        source["findings"].append(second)
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        with self.assertRaises(ValueError):
            _pipeline(provider).review(source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, untouched)

class ReviewCurrentFixIntegrityTest(unittest.TestCase):
    """#901: input must be a canonical nonblank builtin string before models."""

    def _rejected_before_model(self, invalid_fix: object) -> None:
        source = _fixture()
        source["findings"][0]["fix"] = invalid_fix
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        with self.assertRaises(ValueError):
            _pipeline(provider).review(source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, untouched)

    def test_canonical_fix_reaches_advisor_unchanged(self):
        source = _fixture()
        source["findings"][0]["fix"] = "  Configure and retest in lab  "
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        _pipeline(provider).review(source)

        self.assertEqual(source, untouched)
        self.assertEqual(
            _user_payload(provider.requests[1])["current_fix"],
            "  Configure and retest in lab  ",
        )

    @unittest.expectedFailure  # RED until source owner enforces #901
    def test_empty_fix_denied_pre_model(self):
        self._rejected_before_model("")

    @unittest.expectedFailure
    def test_whitespace_only_fix_denied_pre_model(self):
        self._rejected_before_model(" \t\n ")

    @unittest.expectedFailure
    def test_none_fix_denied_pre_model(self):
        self._rejected_before_model(None)

    @unittest.expectedFailure
    def test_integer_fix_denied_pre_model(self):
        self._rejected_before_model(4)

    @unittest.expectedFailure
    def test_boolean_fix_denied_pre_model(self):
        self._rejected_before_model(True)

    @unittest.expectedFailure
    def test_string_subclass_fix_denied_pre_model(self):
        class SpoofedFix(str):
            pass

        self._rejected_before_model(SpoofedFix("Pretend canonical text"))

    @unittest.expectedFailure
    def test_bytes_fix_denied_pre_model(self):
        self._rejected_before_model(b"not JSON-safe text")


    @unittest.expectedFailure  # RED: whole-batch preflight must precede model I/O
    def test_bad_fix_in_second_finding_does_not_emit_first_finding(self):
        source = _fixture()
        second = copy.deepcopy(source["findings"][0])
        second["finding"] = "Second synthetic observation"
        second["fix"] = "  "
        source["findings"].append(second)
        untouched = copy.deepcopy(source)
        provider = RecordingOfflineProvider()

        with self.assertRaises(ValueError):
            _pipeline(provider).review(source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, untouched)

if __name__ == "__main__":
    unittest.main()
