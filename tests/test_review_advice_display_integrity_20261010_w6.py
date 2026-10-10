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
                with self.assertRaises(ValueError):
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
        source["targets"] = ["lab://synthétique"]
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

    def test_noncanonical_model_usage_metadata_denies_at_each_role(self):
        from dataclasses import replace

        # Model-supplied counters are diagnostics only, never authority.
        # Untrusted subclasses and booleans must be denied before downstream
        # model dispatch or the returned ReviewResult.
        invalid = (True, -1, 1_000_001, 1.5, "12", None)

        class IntSubclass(int):
            pass

        for role in AssessmentReviewPipeline.ROLES:
            for field in ("input_tokens", "output_tokens"):
                for value in (*invalid, IntSubclass(5)):
                    with self.subTest(role=role, field=field, value=repr(value)):
                        pipeline, provider = make_pipeline("Synthetic human review")
                        original = provider.complete

                        def tamper(request):
                            reply = original(request)
                            if request.role is role:
                                return replace(reply, **{field: value})
                            return reply

                        provider.complete = tamper
                        with self.assertRaisesRegex(
                            ValueError, "review model response identity is invalid"
                        ):
                            review_with_display_safe_advice(pipeline, fixture())
                        index = AssessmentReviewPipeline.ROLES.index(role) + 1
                        self.assertEqual(
                            [req.role for req in provider.requests],
                            list(AssessmentReviewPipeline.ROLES[:index]),
                        )

    def test_canonical_model_usage_metadata_remains_supported(self):
        from dataclasses import replace

        pipeline, provider = make_pipeline("Synthetic human review")
        original = provider.complete

        def meter(request):
            reply = original(request)
            return replace(reply, input_tokens=200, output_tokens=12)

        provider.complete = meter
        result = review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(result.findings[0].remediation_advice, "Synthetic human review")
        self.assertEqual(len(provider.requests), 3)


    def test_exact_canonical_severity_labels_preserved_and_reported(self):
        for label in ("info", "low", "medium", "high", "critical"):
            with self.subTest(severity=label):
                source = fixture()
                source["findings"][0]["severity"] = label
                before = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic human review")
                result = review_with_display_safe_advice(pipeline, source)
                self.assertEqual(result.findings[0].severity, label)
                self.assertEqual(source, before)
                self.assertEqual(len(provider.requests), 3)

    def test_noncanonical_late_finding_severity_blocks_entire_batch(self):
        invalid = ("HIGH", "High", "critical ", "urgent", "2", "informational")
        for value in invalid:
            with self.subTest(severity=value):
                source = fixture()
                source["findings"].append({
                    **source["findings"][0],
                    "finding": "Later synthetic evidence",
                    "evidence_ids": ["synthetic:evidence:2"],
                    "severity": value,
                })
                before = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic human review")
                with self.assertRaisesRegex(ValueError, "severity is not canonical"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, before)


    def test_provider_failures_are_redacted_at_every_review_role(self):
        secret = "synthetic-private-provider-exception-evidence"
        for role in AssessmentReviewPipeline.ROLES:
            with self.subTest(failing_role=role):
                pipeline, provider = make_pipeline("Synthetic human guidance")
                original = provider.complete

                def fail_at_role(request):
                    if request.role is role:
                        raise RuntimeError(secret + " " + request.role.value)
                    return original(request)

                provider.complete = fail_at_role
                with self.assertRaises(ValueError) as caught:
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual(str(caught.exception), "review model provider failed")
                self.assertNotIn(secret, str(caught.exception))
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertNotIn(
                    ModelRole.REPORT_SYNTHESIZER,
                    [req.role for req in provider.requests]
                    if role is not ModelRole.REPORT_SYNTHESIZER else [],
                )

    def test_invalid_reply_shape_still_uses_specific_safe_validation_error(self):
        pipeline, provider = make_pipeline(" ")
        with self.assertRaisesRegex(ValueError, "invalid bounded advice"):
            review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(
            [request.role for request in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
        )


    def test_aggregate_advisor_bytes_denies_before_report(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(5)
        ]
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Synthetic guidance")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN synthetic"] * 5
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["x" * 8192] * 4 + ["x"]
        with self.assertRaisesRegex(ValueError, "advice batch limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(source, before)
        self.assertEqual(
            [request.role for request in provider.requests],
            [r for _ in range(5) for r in
             (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR)],
        )

    def test_exact_aggregate_boundary_allows_four_canonical_advice_replies(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(4)
        ]
        pipeline, provider = make_pipeline("Synthetic guidance")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN synthetic"] * 4
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["x" * 8192] * 4
        result = review_with_display_safe_advice(pipeline, source)
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(
            [r.role for r in provider.requests].count(ModelRole.REPORT_SYNTHESIZER), 1
        )

    def test_aggregate_advice_budget_counts_utf8_bytes_not_characters(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(5)
        ]
        pipeline, provider = make_pipeline("Synthetic guidance")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN synthetic"] * 5
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["🧪" * 2048] * 4 + ["🧪"]
        with self.assertRaisesRegex(ValueError, "advice batch limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertNotIn(
            ModelRole.REPORT_SYNTHESIZER,
            [request.role for request in provider.requests],
        )


    def test_aggregate_large_source_denies_before_any_model_request(self):
        source = fixture()
        initial = source["findings"][0]
        source["findings"] = [
            {**initial, "finding": "Synthetic " + str(i),
             "impact": "x" * 8000, "fix": "y" * 8000,
             "evidence_summary": "z" * 4000,
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(14)
        ]
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Synthetic guidance")
        with self.assertRaisesRegex(ValueError, "input batch byte limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, before)

    def test_aggregate_budget_counts_unicode_utf8_not_string_length(self):
        source = fixture()
        initial = source["findings"][0]
        source["findings"] = [
            {**initial, "finding": "Synthetic " + str(i),
             "impact": "🧪" * 2000, "fix": "🧪" * 2000,
             "evidence_summary": "🧪" * 1000,
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(14)
        ]
        pipeline, provider = make_pipeline("Synthetic guidance")
        with self.assertRaisesRegex(ValueError, "input batch byte limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])

    def test_reasonable_multifinding_source_budget_still_allows_review(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "impact": "x" * 8000, "fix": "y" * 8000,
             "evidence_summary": "z" * 4000,
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(12)
        ]
        pipeline, provider = make_pipeline("Synthetic guidance")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN synthetic"] * 12
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["Human-only guidance"] * 12
        result = review_with_display_safe_advice(pipeline, source)
        self.assertEqual(len(result.findings), 12)
        self.assertEqual(
            [req.role for req in provider.requests].count(ModelRole.REPORT_SYNTHESIZER),
            1,
        )

    def test_empty_finding_batch_does_not_synthesize_false_assessment(self):
        source = fixture()
        source["findings"] = []
        original = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Synthetic advice only")
        with self.assertRaisesRegex(ValueError, "requires at least one finding"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, original)

    def test_missing_root_target_denies_even_with_row_local_target(self):
        for include_local_target in (False, True):
            with self.subTest(local_target=include_local_target):
                source = fixture()
                del source["target"]
                if include_local_target:
                    source["findings"][0]["target"] = "lab://local-only"
                original = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic advice only")
                with self.assertRaisesRegex(ValueError, "explicit target context"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, original)

    def test_conflicting_single_and_multi_target_sources_deny_pre_model(self):
        for target_list in (
            ["lab://some-other-target"],
            ["lab://inert-fixture-no-network", "lab://different"],
        ):
            with self.subTest(targets=target_list):
                source = fixture()
                source["targets"] = target_list
                original = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic advice only")
                with self.assertRaisesRegex(ValueError, "conflicting target context"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, original)

    def test_target_list_only_and_redundant_matching_target_remain_valid(self):
        for target_context in (
            {"targets": ["lab://first-synthetic"]},
            {"target": "lab://inert-fixture-no-network",
             "targets": ["lab://inert-fixture-no-network"]},
        ):
            with self.subTest(context=target_context):
                source = fixture()
                source.pop("target")
                source.update(target_context)
                original = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic advice only")
                result = review_with_display_safe_advice(pipeline, source)
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(
                    [req.role for req in provider.requests],
                    [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                     ModelRole.REPORT_SYNTHESIZER],
                )
                self.assertEqual(source, original)

    def test_five_bounded_verifier_replies_exceed_aggregate_verdict_limit(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(5)
        ]
        original = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Simple human review")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN " + "x" * 8182] * 5
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["Check manually"] * 5
        with self.assertRaisesRegex(ValueError, "verdict batch limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(source, original)
        self.assertEqual(
            [request.role for request in provider.requests],
            [role for _ in range(4) for role in
             (ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR)]
            + [ModelRole.VERIFIER],
        )
        self.assertNotIn(
            ModelRole.REPORT_SYNTHESIZER,
            [request.role for request in provider.requests],
        )

    def test_four_full_verifier_replies_fit_exact_total_byte_budget(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(4)
        ]
        pipeline, provider = make_pipeline("Simple human review")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN " + "x" * 8182] * 4
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["Check manually"] * 4
        result = review_with_display_safe_advice(pipeline, source)
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(
            [request.role for request in provider.requests].count(
                ModelRole.REPORT_SYNTHESIZER
            ), 1,
        )

    def test_multibyte_verifier_budget_uses_encoded_bytes(self):
        source = fixture()
        first = source["findings"][0]
        source["findings"] = [
            {**first, "finding": "Synthetic " + str(i),
             "evidence_ids": ["synthetic:evidence:" + str(i)]}
            for i in range(5)
        ]
        pipeline, provider = make_pipeline("Simple human review")
        provider._script[ModelRole.VERIFIER] = ["UNCERTAIN " + "🧪" * 2045] * 5
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["Check manually"] * 5
        with self.assertRaisesRegex(ValueError, "verdict batch limit exceeded"):
            review_with_display_safe_advice(pipeline, source)
        self.assertNotIn(
            ModelRole.REPORT_SYNTHESIZER,
            [request.role for request in provider.requests],
        )

    def test_duplicate_declared_target_identity_denies_without_provider_calls(self):
        source = fixture()
        source.pop("target")
        source["targets"] = ["lab://same", "lab://same"]
        source["findings"][0]["target"] = "lab://same"
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Synthetic human advice")
        with self.assertRaisesRegex(ValueError, "duplicate target context"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, before)

    def test_multitarget_review_requires_each_finding_target(self):
        source = fixture()
        source.pop("target")
        source["targets"] = ["lab://one", "lab://two"]
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline("Synthetic human advice")
        with self.assertRaisesRegex(ValueError, "requires finding target context"):
            review_with_display_safe_advice(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, before)

    def test_later_finding_outside_declared_target_set_denies_whole_batch(self):
        for scenario in ("single_root", "multi_target"):
            with self.subTest(scenario=scenario):
                source = fixture()
                if scenario == "single_root":
                    source["findings"][0]["target"] = source["target"]
                else:
                    source.pop("target")
                    source["targets"] = ["lab://one", "lab://two"]
                    source["findings"][0]["target"] = "lab://one"
                source["findings"].append({
                    **source["findings"][0], "finding": "Later synthetic claim",
                    "evidence_ids": ["synthetic:evidence:other"],
                    "target": "lab://out-of-set",
                })
                before = copy.deepcopy(source)
                pipeline, provider = make_pipeline("Synthetic human advice")
                with self.assertRaisesRegex(ValueError, "outside declared context"):
                    review_with_display_safe_advice(pipeline, source)
                self.assertEqual(provider.requests, [])
                self.assertEqual(source, before)

    def test_canonical_multitarget_mapping_reaches_verifier_exactly(self):
        import json

        source = fixture()
        source.pop("target")
        source["targets"] = ["lab://one", "lab://two"]
        source["findings"][0]["target"] = "lab://one"
        source["findings"].append({
            **source["findings"][0], "finding": "Later synthetic claim",
            "evidence_ids": ["synthetic:evidence:2"], "target": "lab://two",
        })
        before = copy.deepcopy(source)
        pipeline, provider = make_pipeline(
            "Human check for first evidence", "Human check for second evidence"
        )
        result = review_with_display_safe_advice(pipeline, source)
        verifier_requests = [
            req for req in provider.requests if req.role is ModelRole.VERIFIER
        ]
        self.assertEqual(
            [json.loads(req.messages[-1].content)["target"]
             for req in verifier_requests],
            ["lab://one", "lab://two"],
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(source, before)

    def test_multiline_verifier_status_smuggling_denies_before_advisor(self):
        for verdict in (
            "UNCERTAIN synthetic evidence\nCONFIRMED synthetic claim",
            "REJECTED synthetic finding\nCONFIRMED fabricated proof",
            "CONFIRMED fake source\nUNCERTAIN contradicting detail",
            "UNCERTAIN\tCONFIRMED",
        ):
            with self.subTest(verdict=verdict):
                pipeline, provider = make_pipeline("Synthetic human-only advice")
                provider._script[ModelRole.VERIFIER] = [verdict]
                with self.assertRaisesRegex(ValueError, "must be a single line"):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual(
                    [request.role for request in provider.requests],
                    [ModelRole.VERIFIER],
                )

    def test_single_line_verifier_reason_keeps_exact_text(self):
        import json

        verifier = "UNCERTAIN Aucun élément vérifié. 人工確認。"
        pipeline, provider = make_pipeline("Synthetic human-only advice")
        provider._script[ModelRole.VERIFIER] = [verifier]
        result = review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(result.findings[0].verdict, verifier)
        advisor = next(request for request in provider.requests
                       if request.role is ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(
            json.loads(advisor.messages[-1].content)["verifier_verdict"],
            verifier,
        )

    def test_in_place_frozen_role_binding_mutation_rejected_pre_advisor(self):
        for field in ("model_id", "provider_id"):
            with self.subTest(field=field):
                pipeline, provider = make_pipeline("Human-only remediation advice")
                gateway = pipeline.gateway
                original = provider.complete

                def corrupt_binding(request):
                    response = original(request)
                    if request.role is ModelRole.VERIFIER:
                        binding = gateway._bindings[ModelRole.REMEDIATION_ADVISOR]
                        # Dataclass(frozen=True) is not a true deep-freeze;
                        # this attack modifies the same aliased object.
                        object.__setattr__(binding, field, "injected-binding")
                    return response

                provider.complete = corrupt_binding
                with self.assertRaisesRegex(ValueError, "binding changed"):
                    review_with_display_safe_advice(pipeline, fixture())
                self.assertEqual(
                    [req.role for req in provider.requests],
                    [ModelRole.VERIFIER],
                )

    def test_active_verifier_frozen_binding_mutation_rejected_after_reply(self):
        pipeline, provider = make_pipeline("Human-only remediation advice")
        gateway = pipeline.gateway
        original = provider.complete

        def corrupt_active_binding(request):
            response = original(request)
            if request.role is ModelRole.VERIFIER:
                binding = gateway._bindings[ModelRole.VERIFIER]
                object.__setattr__(binding, "model_id", "injected-model")
            return response

        provider.complete = corrupt_active_binding
        with self.assertRaisesRegex(ValueError, "binding changed"):
            review_with_display_safe_advice(pipeline, fixture())
        self.assertEqual(
            [req.role for req in provider.requests],
            [ModelRole.VERIFIER],
        )

if __name__ == "__main__":
    unittest.main()
