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


    def test_every_forwarded_presentation_field_denies_controls_pre_model(self):
        # Alter exactly one independent synthetic field at a time. A late
        # finding must not dispatch an earlier one to any provider.
        for field in ("finding", "severity", "impact", "evidence_summary",
                      "target", "fix"):
            with self.subTest(field=field):
                source = fixture()
                row = dict(source["findings"][0])
                row["finding"] = "Second synthetic finding"
                row["evidence_ids"] = ["synthetic:evidence:2"]
                row[field] = "unsafe\u202evalue"
                source["findings"].append(row)
                before = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Valid advice")
                with self.assertRaisesRegex(ValueError, "review input display"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, before)

    def test_evidence_reference_and_root_target_controls_deny_pre_model(self):
        for path in ("evidence_id", "root_target", "targets", "count_key"):
            with self.subTest(path=path):
                source = fixture()
                if path == "evidence_id":
                    source["findings"][0]["evidence_ids"][0] += "\u200b"
                if path == "root_target":
                    source["target"] += "\x1b"
                if path == "targets":
                    source["targets"] = ["lab://clean", "lab://bad\u2069"]
                if path == "count_key":
                    source["coverage"]["counts"]["unsafe\u202e"] = 1
                before = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Valid advice")
                with self.assertRaisesRegex(ValueError, "review input display"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, before)

    def test_safe_unicode_review_inputs_are_not_changed(self):
        source = fixture()
        source["target"] = "lab://synthétique"
        source["targets"] = ["lab://合成"]
        source["findings"][0]["finding"] = "Évaluation synthétique"
        source["findings"][0]["impact"] = "测试摘要"
        source["findings"][0]["evidence_summary"] = "Échantillon contrôlé"
        source["findings"][0]["evidence_ids"] = ["synthetic:résumé"]
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Human review advised.")
        result = review_with_display_safe_advice(pipeline, source)
        self.assertEqual(source, before)
        self.assertEqual(result.findings[0].title, "Évaluation synthétique")
        import json
        verifier = next(r for r in provider.requests if r.role is ModelRole.VERIFIER)
        self.assertEqual(
            json.loads(verifier.messages[-1].content)["evidence_ids"], ["synthetic:résumé"]
        )
        self.assertEqual(json.loads(verifier.messages[-1].content)["finding"], "Évaluation synthétique")

    def test_verifier_wrong_model_or_role_denies_before_advisor(self):
        from dataclasses import replace
        for change in ({"model_id": "spoofed-model"},
                       {"role": ModelRole.REPORT_SYNTHESIZER},
                       {"content": "\u202eFAKE UNCERTAIN"},
                       {"content": " \n\t "}):
            with self.subTest(change=change):
                pipeline, provider = make_pipeline("Valid advisor guidance")
                original = provider.complete

                def altered(req):
                    response = original(req)
                    if req.role is ModelRole.VERIFIER:
                        return replace(response, **change)
                    return response

                provider.complete = altered
                with self.assertRaises(ValueError):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual(
                    [r.role for r in provider.requests], [ModelRole.VERIFIER]
                )

    def test_report_wrong_role_model_blank_or_control_never_returned(self):
        from dataclasses import replace
        for change in ({"model_id": "spoofed-model"},
                       {"role": ModelRole.VERIFIER},
                       {"content": ""},
                       {"content": "\u202efalse safety report"}):
            with self.subTest(change=change):
                pipeline, provider = make_pipeline("Valid advisor guidance")
                original = provider.complete

                def altered(req):
                    response = original(req)
                    if req.role is ModelRole.REPORT_SYNTHESIZER:
                        return replace(response, **change)
                    return response

                provider.complete = altered
                with self.assertRaises(ValueError):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual(
                    [r.role for r in provider.requests],
                    [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                     ModelRole.REPORT_SYNTHESIZER],
                )

    def test_output_rejection_error_does_not_echo_provider_content(self):
        from dataclasses import replace
        secret_marker = "synthetic-sentinel-never-log-this"
        pipeline, provider = make_pipeline("Valid advice")
        original = provider.complete

        def altered(req):
            response = original(req)
            if req.role is ModelRole.REPORT_SYNTHESIZER:
                return replace(response, content=secret_marker + "\u202e")
            return response

        provider.complete = altered
        with self.assertRaises(ValueError) as caught:
            review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(str(caught.exception),
                         "review model response display text is invalid")
        self.assertNotIn(secret_marker, str(caught.exception))


    def test_mid_review_future_role_rebinding_denied_before_next_request(self):
        for change_at, target_role, expected in (
            (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
             [ModelRole.VERIFIER]),
            (ModelRole.REMEDIATION_ADVISOR, ModelRole.REPORT_SYNTHESIZER,
             [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR]),
        ):
            with self.subTest(change_at=change_at, target_role=target_role):
                pipeline, provider = make_pipeline("Human-only review guidance.")
                gateway = pipeline.gateway
                original = provider.complete

                def mutate(req):
                    response = original(req)
                    if req.role is change_at:
                        gateway.bind_role(target_role, provider.provider_id, "changed-model")
                    return response

                provider.complete = mutate
                with self.assertRaisesRegex(ValueError, "binding changed"):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual([r.role for r in provider.requests], expected)

    def test_mid_review_active_role_rebinding_denied_after_response(self):
        pipeline, provider = make_pipeline("Human-only review guidance.")
        gateway = pipeline.gateway
        original = provider.complete

        def mutate_verifier(req):
            response = original(req)
            if req.role is ModelRole.VERIFIER:
                gateway.bind_role(ModelRole.VERIFIER, provider.provider_id,
                                  "changed-after-request")
            return response

        provider.complete = mutate_verifier
        with self.assertRaisesRegex(ValueError, "binding changed"):
            review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual([r.role for r in provider.requests], [ModelRole.VERIFIER])

    def test_unchanged_model_bindings_keep_expected_model_ids(self):
        pipeline, provider = make_pipeline("Synthetic reviewer guidance.")
        result = review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(
            [r.model_id for r in provider.requests], ["local-script"] * 3
        )
        self.assertEqual(
            {role for role, _ in result.model_bindings},
            {role.value for role in AssessmentReviewPipeline.ROLES},
        )


    def test_mutable_provider_registry_replacement_denied_mid_review(self):
        for swap_at, expected in (
            (ModelRole.VERIFIER, [ModelRole.VERIFIER]),
            (ModelRole.REMEDIATION_ADVISOR,
             [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR]),
        ):
            with self.subTest(swap_at=swap_at):
                pipeline, provider = make_pipeline("Synthetic human review")
                gateway = pipeline.gateway
                original = provider.complete

                def swap_provider(req):
                    response = original(req)
                    if req.role is swap_at:
                        # Same registered provider ID, different object. The
                        # provider-id-only ModelGateway contract cannot see it.
                        gateway._providers[provider.provider_id] = ScriptedProvider(
                            provider.provider_id, {
                                ModelRole.VERIFIER: ["UNCERTAIN altered script"],
                                ModelRole.REMEDIATION_ADVISOR: ["Altered advice"],
                                ModelRole.REPORT_SYNTHESIZER: ["Altered report"],
                            }
                        )
                    return response

                provider.complete = swap_provider
                with self.assertRaisesRegex(ValueError, "provider instance changed"):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual([r.role for r in provider.requests], expected)

if __name__ == "__main__":
    unittest.main()
