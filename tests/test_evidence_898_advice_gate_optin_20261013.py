"""Real gateway/pipeline acceptance for the UNINSTALLED #898 advice adapter.

All interactions are deterministic ScriptedProvider calls, not real AI models,
targets, grants, assessments or remediation/retest executions.
"""
from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.remediation_advice_gate_optin import (
    CheckedRemediationAdviceProvider,
)


class StrSubclass(str):
    pass


def _fixture(*, finding_count=1):
    base = {
        "finding": "Synthetic finding",
        "severity": "low",
        "impact": "No live impact",
        "fix": "Ask a human to review a mitigation.",
        "target": "lab://offline-fixture",
        "evidence_ids": ["fixture-evidence-ref"],
        "evidence_summary": "An offline, generated observation.",
    }
    return {
        "target": "lab://offline-fixture",
        "findings": [dict(base, finding=f"Synthetic {index}") for index in range(finding_count)],
        "coverage": {"counts": {"assessed": 1, "unknown": 1}},
    }


class RecordingProvider(ScriptedProvider):
    def __init__(self, advice, *, findings=1):
        super().__init__(
            "offline-advisor-gate-fixture",
            {
                ModelRole.VERIFIER: ["CONFIRMED synthetic evidence"] * findings,
                ModelRole.REMEDIATION_ADVISOR: (
                    advice if type(advice) is list else [advice]
                ),
                ModelRole.REPORT_SYNTHESIZER: ["Synthetic summary, no real verdict"],
            },
        )
        self.roles = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.roles.append(request.role)
        return super().complete(request)


def _run(provider: RecordingProvider, payload: dict, *, cap=8192):
    gateway = ModelGateway()
    checked = CheckedRemediationAdviceProvider(provider, max_advice_chars=cap)
    gateway.register_provider(checked)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, checked.provider_id, "offline-script")
    return AssessmentReviewPipeline(gateway).review(payload)


class AdviceGateOptInPipelineAcceptance(unittest.TestCase):
    def _assert_denied_before_report(self, advice, *, expected_findings=1):
        payload = _fixture(finding_count=expected_findings)
        original = copy.deepcopy(payload)
        provider = RecordingProvider(advice, findings=expected_findings)
        with self.assertRaisesRegex(
            ValueError, "remediation advice must be bounded non-empty text"
        ) as caught:
            _run(provider, payload)
        self.assertNotIn("PRIVATE_", str(caught.exception))
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)
        self.assertEqual(payload, original)
        self.assertEqual(
            provider.roles[0:2],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
        )
        return provider.roles

    def test_valid_literal_remediation_text_flows_to_report_once(self):
        text = "Apply the fixture change; verify with an independent lab test."
        payload = _fixture()
        before = copy.deepcopy(payload)
        provider = RecordingProvider(text)
        result = _run(provider, payload)
        self.assertEqual(result.findings[0].remediation_advice, text)
        self.assertEqual(payload, before)
        self.assertEqual(provider.roles, [
            ModelRole.VERIFIER,
            ModelRole.REMEDIATION_ADVISOR,
            ModelRole.REPORT_SYNTHESIZER,
        ])

    def test_unicode_nonblank_text_remains_byte_identical(self):
        text = "Controleer deze wijziging 🔐 en test opnieuw in het lab."
        provider = RecordingProvider(text)
        result = _run(provider, _fixture())
        self.assertEqual(result.findings[0].remediation_advice.encode(), text.encode())

    def test_none_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(None)

    def test_empty_advisor_output_denied_before_report(self):
        self._assert_denied_before_report("")

    def test_ascii_whitespace_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(" \t\r\n ")

    def test_unicode_whitespace_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(" \u00a0\u2003\u202f ")

    def test_bytes_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(b"PRIVATE_invalid_byte_advice")

    def test_integer_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(42)

    def test_str_subclass_advisor_output_denied_before_report(self):
        self._assert_denied_before_report(StrSubclass("apparently okay"))

    def test_lone_surrogate_fails_without_unicode_exception_context(self):
        payload = _fixture()
        provider = RecordingProvider("PRIVATE_\ud800")
        with self.assertRaisesRegex(
            ValueError, "remediation advice must be bounded non-empty text"
        ) as caught:
            _run(provider, payload)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_max_character_limit_accepts_exact_length(self):
        provider = RecordingProvider("a" * 64)
        result = _run(provider, _fixture(), cap=64)
        self.assertEqual(result.findings[0].remediation_advice, "a" * 64)

    def test_max_character_limit_rejects_before_report(self):
        payload = _fixture()
        provider = RecordingProvider("a" * 65)
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, payload, cap=64)
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_extremely_oversized_advice_rejected_before_report(self):
        # Regression for the old ordering: avoid calling .strip() on an
        # attacker-sized advisor string before checking the exact char cap.
        huge = (" " * (8 * 1024 * 1024)) + "secret"
        provider = RecordingProvider(huge)
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, _fixture())
        self.assertEqual(provider.roles, [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
        ])

    def test_multibyte_utf8_overflow_denied_even_under_character_limit(self):
        self._assert_denied_before_report("🔐" * 4097)

    def test_multibyte_utf8_exact_byte_cap_remains_accepted(self):
        text = "🔐" * 4096
        result = _run(RecordingProvider(text), _fixture())
        self.assertEqual(result.findings[0].remediation_advice, text)

    def test_late_second_finding_failure_does_not_dispatch_report(self):
        payload = _fixture(finding_count=2)
        before = copy.deepcopy(payload)
        provider = RecordingProvider(["Validated first", "  \n "], findings=2)
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, payload)
        self.assertEqual(payload, before)
        self.assertEqual(provider.roles, [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
        ])

    def test_wrong_role_in_advisor_response_is_refused(self):
        class WrongRoleProvider(RecordingProvider):
            def complete(self, request):
                response = super().complete(request)
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    return replace(response, role=ModelRole.REPORT_SYNTHESIZER)
                return response
        provider = WrongRoleProvider("apparently valid")
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, _fixture())
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_advisor_response_provider_identity_mismatch_denied_before_report(self):
        class WrongProviderIdentity(RecordingProvider):
            def complete(self, request):
                response = super().complete(request)
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    return replace(response, provider_id="other-untrusted-provider")
                return response
        provider = WrongProviderIdentity("apparently valid")
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, _fixture())
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_advisor_response_model_identity_mismatch_denied_before_report(self):
        class WrongModelIdentity(RecordingProvider):
            def complete(self, request):
                response = super().complete(request)
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    return replace(response, model_id="swapped-model")
                return response
        provider = WrongModelIdentity("apparently valid")
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            _run(provider, _fixture())
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_delegate_identity_is_pinned_against_in_place_mutation(self):
        provider = RecordingProvider("apparently valid")
        gate = CheckedRemediationAdviceProvider(provider)
        before = gate.provider_id
        provider._provider_id = "swapped-provider-after-binding"
        self.assertEqual(gate.provider_id, before)
        gateway = ModelGateway()
        gateway.register_provider(gate)
        for role in AssessmentReviewPipeline.ROLES:
            gateway.bind_role(role, before, "offline-script")
        with self.assertRaisesRegex(ValueError, "bounded non-empty text"):
            AssessmentReviewPipeline(gateway).review(_fixture())
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER, provider.roles)

    def test_advisor_provider_exception_sanitized_without_context_leak(self):
        class RaisingAdvisor(RecordingProvider):
            def complete(self, request):
                if request.role is ModelRole.REMEDIATION_ADVISOR:
                    self.roles.append(request.role)
                    raise RuntimeError("PRIVATE_PROVIDER_CREDENTIALS")
                return super().complete(request)
        provider = RaisingAdvisor("unused")
        with self.assertRaisesRegex(ValueError, "bounded non-empty text") as caught:
            _run(provider, _fixture())
        self.assertNotIn("PRIVATE_", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(provider.roles, [
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR
        ])

    def test_non_advisor_failures_are_not_silently_converted(self):
        class RaisingVerifier(RecordingProvider):
            def complete(self, request):
                if request.role is ModelRole.VERIFIER:
                    raise RuntimeError("synthetic verifier error")
                return super().complete(request)
        # The gate is scoped to ADVISOR only; other owner roles remain the
        # default gateway's responsibility, not reinterpreted by this helper.
        with self.assertRaisesRegex(RuntimeError, "synthetic verifier error"):
            _run(RaisingVerifier("unused"), _fixture())

    def test_invalid_configuration_fails_before_provider_dispatch(self):
        for value in (True, False, 0, -1, 8193, 1.5, "64"):
            with self.subTest(limit=value):
                p = RecordingProvider("valid")
                with self.assertRaises(ValueError):
                    CheckedRemediationAdviceProvider(p, max_advice_chars=value)
                self.assertEqual(p.roles, [])

    def test_non_advisor_response_preserves_provider_identity(self):
        p = RecordingProvider("valid")
        w = CheckedRemediationAdviceProvider(p)
        self.assertEqual(w.provider_id, p.provider_id)
        result = _run(p, _fixture())
        self.assertEqual(result.model_bindings[0][0], ModelRole.VERIFIER.value)


if __name__ == "__main__":
    unittest.main()
