"""Offline, synthetic evidence-remediation advisor display regression tests.

All models are ScriptedProvider stubs; no targets, sockets, durable data,
real approval, external model or remediation/retest execution is involved.
"""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.review_advice_display_integrity import (
    checked_remediation_display_text, review_with_display_safe_advice,
)


class RecordingSyntheticProvider(ScriptedProvider):
    def __init__(self, advice: object, second_advice: object | None = None):
        choices = [advice] if second_advice is None else [advice, second_advice]
        super().__init__("offline-advice-display", {
            ModelRole.VERIFIER: ["UNCERTAIN synthetic evidence"] * 2,
            ModelRole.REMEDIATION_ADVISOR: choices,
            ModelRole.REPORT_SYNTHESIZER: ["Unverified synthetic report"],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def make_pipeline(advice: object, second_advice: object | None = None):
    provider = RecordingSyntheticProvider(advice, second_advice)
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "local-script")
    return AssessmentReviewPipeline(gateway), provider


def fixture():
    return {
        "target": "lab://inert-fixture-no-network",
        "findings": [{
            "finding": "Synthetic review request",
            "severity": "low",
            "impact": "No actual target or impact",
            "fix": "Human check for a synthetic claim",
            "evidence_summary": "Synthetic context; no real evidence verified",
            "evidence_ids": ["synthetic:evidence:1"],
        }],
        "coverage": {"counts": {"reviewed": 0}},
    }


class AdviceDisplayIntegrityTests(unittest.TestCase):
    def test_valid_multiline_and_non_ascii_preserved_byte_for_byte(self):
        advice = "\tÉtape une: contrôlez manuellement.\n步骤二：保留证据。  "
        pipeline, provider = make_pipeline(advice)
        original = fixture()
        before = copy.deepcopy(original)
        result = review_with_display_safe_advice(pipeline, original)
        self.assertEqual(result.findings[0].remediation_advice, advice)
        self.assertEqual(result.report, "Unverified synthetic report")
        self.assertEqual(original, before)
        self.assertEqual(
            [r.role for r in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
             ModelRole.REPORT_SYNTHESIZER],
        )

    def test_text_validator_is_identity_preserving(self):
        value = " Préserver les éléments de preuve.\nRevue humaine. "
        self.assertIs(checked_remediation_display_text(value), value)

    def test_nonprinting_unicode_does_not_reach_report(self):
        for control in (
            "\x00", "\x1b", "\x7f", "\u0085", "\u202e", "\u202a",
            "\u2067", "\u2069", "\u200d", "\u200b", "\ud800",
            "\ue000", "\uffff",
        ):
            with self.subTest(char=ascii(control)):
                pipeline, provider = make_pipeline("Review " + control + " evidence")
                source = fixture()
                before = copy.deepcopy(source)
                with self.assertRaisesRegex(ValueError, "display text is invalid"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(source, before)
                self.assertEqual(
                    [r.role for r in provider.requests],
                    [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
                )

    def test_bad_second_response_never_invokes_report(self):
        pipeline, provider = make_pipeline(
            "First synthetic advice", "Second\u202eadvice"
        )
        source = fixture()
        source["findings"].append({
            **source["findings"][0], "finding": "Second synthetic finding",
            "evidence_ids": ["synthetic:evidence:2"],
        })
        before = copy.deepcopy(source)
        with self.assertRaisesRegex(ValueError, "display text is invalid"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(source, before)
        self.assertEqual(
            [r.role for r in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
             ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
        )

    def test_empty_and_blank_advice_rejected_before_report(self):
        for text in ("", "  \n\t "):
            with self.subTest(text=repr(text)):
                pipeline, provider = make_pipeline(text)
                with self.assertRaises(ValueError):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertNotIn(
                    ModelRole.REPORT_SYNTHESIZER, [r.role for r in provider.requests]
                )

    def test_byte_limit_rejects_oversized_multibyte_response(self):
        valid = "\U0001F9EA" * 4096
        invalid = valid + "\U0001F9EA"
        self.assertIs(checked_remediation_display_text(valid), valid)
        with self.assertRaisesRegex(ValueError, "display text is invalid"):
            checked_remediation_display_text(invalid)
        pipeline, provider = make_pipeline(invalid)
        with self.assertRaises(ValueError):
            review_with_display_safe_advice(pipeline, fixture())
        self.assertNotIn(
            ModelRole.REPORT_SYNTHESIZER, [r.role for r in provider.requests]
        )

    def test_character_limit_applies_independently_of_bytes(self):
        allowed = "x" * 8192
        self.assertIs(checked_remediation_display_text(allowed), allowed)
        with self.assertRaises(ValueError):
            checked_remediation_display_text(allowed + "x")

    def test_subclass_and_nonstring_reject_without_user_callbacks(self):
        class UnsafeText(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("untrusted strip called")
        for text in (UnsafeText("safe looking text"), None, 42, b"bytes", True):
            with self.subTest(kind=type(text).__name__):
                with self.assertRaisesRegex(ValueError, "display text is invalid"):
                    checked_remediation_display_text(text)

    def test_invalid_second_finding_is_preflight_rejected_with_zero_model_calls(self):
        source = fixture()
        source["findings"].append({
            **source["findings"][0], "finding": "Malformed later claim", "fix": None,
            "evidence_ids": ["synthetic:evidence:2"],
        })
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Good text")
        with self.assertRaises(ValueError):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, before)

    def test_duplicate_evidence_ref_denies_before_all_model_calls(self):
        source = fixture()
        source["findings"][0]["evidence_ids"].append("synthetic:evidence:1")
        pipeline, provider = make_pipeline("Good text")
        with self.assertRaisesRegex(ValueError, "duplicate evidence reference"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])

    def test_incompatible_pipeline_rejected_before_io(self):
        with self.assertRaisesRegex(ValueError, "canonical review pipeline"):
            review_with_display_safe_advice(object(), fixture())



    def test_rejected_advice_never_leaks_private_text_in_error(self):
        marker = "offline-private-test-marker-do-not-publish"
        pipeline, provider = make_pipeline(marker + "\u202e")
        source = fixture()
        with self.assertRaises(ValueError) as caught:
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(str(caught.exception), "remediation advice display text is invalid")
        self.assertNotIn(marker, str(caught.exception))
        self.assertNotIn(ModelRole.REPORT_SYNTHESIZER,
                         [request.role for request in provider.requests])

    def test_untrusted_advice_subclass_never_invokes_user_text_methods(self):
        class CallbackText(str):
            def strip(self, *args, **kwargs):
                raise AssertionError("untrusted model output callback invoked")

        pipeline, provider = make_pipeline(CallbackText("looks printable"))
        with self.assertRaisesRegex(ValueError, "invalid bounded advice"):
            review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(
            [request.role for request in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
        )


    def test_hidden_control_in_later_current_fix_blocks_entire_model_batch(self):
        source = fixture()
        source["findings"].append({
            **source["findings"][0],
            "finding": "Untrusted second finding",
            "fix": "Do not reorder\u202ethe human fix",
            "evidence_ids": ["synthetic:evidence:2"],
        })
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Safe synthetic advice")
        with self.assertRaisesRegex(ValueError, "display text is invalid"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, before)

    def test_safe_multiline_current_fix_reaches_advisor_unchanged(self):
        source = fixture()
        fix = "  Human action one.\n\tStep two: preserve evidence. "
        source["findings"][0]["fix"] = fix
        pipeline, provider = make_pipeline("Synthetic safe review.")
        result = review_with_display_safe_advice(pipeline, source)
        advisor = next(request for request in provider.requests
                       if request.role is ModelRole.REMEDIATION_ADVISOR)
        # The gateway sends the canonical structured payload; it must not
        # strip, normalize, repair or rewrite the human-authored current fix.
        import json
        payload = json.loads(advisor.messages[-1].content)
        self.assertEqual(payload["current_fix"], fix)
        self.assertEqual(result.findings[0].remediation_advice, "Synthetic safe review.")

if __name__ == "__main__":
    unittest.main()
