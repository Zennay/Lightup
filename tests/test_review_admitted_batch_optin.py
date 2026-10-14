"""Safe deterministic ScriptedProvider tests for opt-in admitted review adapter.

All findings and model completions are synthetic. No remote model, target,
database or scope mutation is permitted by this fixture.
"""
from __future__ import annotations

import copy
import json
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.review_admitted_batch_optin import review_admitted_remediation_batch


class RecordingScriptedProvider(ScriptedProvider):
    def __init__(self, on_first_request=None):
        super().__init__("offline-only", {
            ModelRole.VERIFIER: ["UNCERTAIN synthetic evidence needs verification"] * 4,
            ModelRole.REMEDIATION_ADVISOR: ["Synthetic fix and retest advice"] * 4,
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic client report, not a verdict."],
        })
        self.requests: list[ModelRequest] = []
        self.on_first_request = on_first_request

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if len(self.requests) == 1 and self.on_first_request is not None:
            self.on_first_request()
        return super().complete(request)


def bound_pipeline(provider):
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "scripted-offline")
    return AssessmentReviewPipeline(gateway)


def fixture_finding(name="synthetic-1", fix="  Change config and retest  ", refs=None):
    return {
        "finding": f"Synthetic finding {name}",
        "severity": "medium",
        "impact": f"Synthetic impact for {name}",
        "target": f"asset://offline/{name}",
        "fix": fix,
        "evidence_ids": [f"evidence:{name}"] if refs is None else refs,
        "evidence_summary": f"Synthetic evidence summary for {name}.",
        "evidence_payload": "SYNTHETIC-PRIVATE-RAW-DO-NOT-FORWARD",
        "untrusted_extra": "synthetic-untrusted-extra",
    }


def fixture(*items):
    return {
        "target": "asset://caller-top-level",
        "findings": list(items),
        "coverage": {"counts": {"assessed": 999999, "unknown": 0}},
        "evidence_payload": "SYNTHETIC-TOP-LEVEL-PRIVATE-RAW",
        "unknown_authorization_grant": "fake-grant",
    }


def user_payload(request: ModelRequest) -> dict:
    return json.loads(next(m.content for m in request.messages if m.role == "user"))


class OptinAdmittedReviewAdapterTest(unittest.TestCase):
    def test_single_canonical_item_roundtrip_preserves_fix_and_context(self):
        original = fixture(fixture_finding())
        before = copy.deepcopy(original)
        provider = RecordingScriptedProvider()
        result = review_admitted_remediation_batch(bound_pipeline(provider), original)
        self.assertEqual(original, before)
        self.assertEqual(result.findings[0].verdict, "UNCERTAIN synthetic evidence needs verification")
        self.assertEqual(result.findings[0].remediation_advice, "Synthetic fix and retest advice")
        self.assertEqual(
            [request.role for request in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR, ModelRole.REPORT_SYNTHESIZER],
        )
        self.assertEqual(user_payload(provider.requests[1])["current_fix"],
                         "  Change config and retest  ")
        self.assertEqual(user_payload(provider.requests[1])["evidence_ids"],
                         ["evidence:synthetic-1"])
        self.assertEqual(user_payload(provider.requests[2])["target"],
                         "asset://offline/synthetic-1")

    def test_all_dispatched_user_payloads_exclude_raw_evidence_and_fake_grant(self):
        provider = RecordingScriptedProvider()
        review_admitted_remediation_batch(bound_pipeline(provider), fixture(fixture_finding()))
        dumped = "\n".join(
            str(user_payload(request)) for request in provider.requests
        )
        for disallowed in (
            "SYNTHETIC-PRIVATE-RAW-DO-NOT-FORWARD",
            "SYNTHETIC-TOP-LEVEL-PRIVATE-RAW",
            "fake-grant",
            "synthetic-untrusted-extra",
            "999999",
            "unknown_authorization_grant",
        ):
            self.assertNotIn(disallowed, dumped)

    def test_multiple_findings_remain_distinct_and_target_not_misattributed(self):
        provider = RecordingScriptedProvider()
        result = review_admitted_remediation_batch(
            bound_pipeline(provider),
            fixture(fixture_finding("one", "Fix one"),
                    fixture_finding("two", "Fix two")),
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(
            [user_payload(request)["current_fix"] for request in provider.requests
             if request.role is ModelRole.REMEDIATION_ADVISOR],
            ["Fix one", "Fix two"],
        )
        self.assertEqual(
            user_payload(provider.requests[-1])["target"],
            "Multiple preflighted target labels",
        )
        self.assertEqual(
            [request.role for request in provider.requests],
            [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR] * 2
            + [ModelRole.REPORT_SYNTHESIZER],
        )

    def test_late_blank_fix_rejects_before_any_provider_call(self):
        provider = RecordingScriptedProvider()
        invalid = fixture(
            fixture_finding("early", "Valid fix"),
            fixture_finding("late", " \n "),
        )
        before = copy.deepcopy(invalid)
        with self.assertRaisesRegex(ValueError, "remediation"):
            review_admitted_remediation_batch(bound_pipeline(provider), invalid)
        self.assertEqual(provider.requests, [])
        self.assertEqual(invalid, before)

    def test_late_duplicate_ref_rejects_before_any_provider_call(self):
        provider = RecordingScriptedProvider()
        invalid = fixture(
            fixture_finding("early", "Valid fix"),
            fixture_finding("late", "Also valid", ["same", "same"]),
        )
        before = copy.deepcopy(invalid)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            review_admitted_remediation_batch(bound_pipeline(provider), invalid)
        self.assertEqual(provider.requests, [])
        self.assertEqual(invalid, before)

    def test_late_invalid_type_rejects_before_any_provider_call(self):
        provider = RecordingScriptedProvider()
        invalid = fixture(fixture_finding("early"), fixture_finding("late", 13))
        with self.assertRaisesRegex(ValueError, "remediation"):
            review_admitted_remediation_batch(bound_pipeline(provider), invalid)
        self.assertEqual(provider.requests, [])

    def test_mutation_after_first_model_request_cannot_change_later_requests(self):
        initial = fixture(fixture_finding("one", "Accepted first"),
                          fixture_finding("two", "Accepted second"))
        def mutate_original():
            initial["findings"][0]["fix"] = "CHANGED AFTER ADMISSION"
            initial["findings"][1]["fix"] = "CHANGED SECOND"
            initial["findings"][1]["evidence_ids"][:] = ["attacker:replacement"]
            initial["findings"].clear()
            initial["target"] = "asset://forged"
        provider = RecordingScriptedProvider(on_first_request=mutate_original)
        result = review_admitted_remediation_batch(bound_pipeline(provider), initial)
        self.assertEqual(len(result.findings), 2)
        advisors = [
            user_payload(request) for request in provider.requests
            if request.role is ModelRole.REMEDIATION_ADVISOR
        ]
        self.assertEqual([payload["current_fix"] for payload in advisors],
                         ["Accepted first", "Accepted second"])
        self.assertEqual(advisors[1]["evidence_ids"], ["evidence:two"])
        self.assertNotIn("asset://forged",
                         str(user_payload(provider.requests[-1])))

    def test_empty_batch_still_reports_without_claiming_coverage(self):
        provider = RecordingScriptedProvider()
        result = review_admitted_remediation_batch(bound_pipeline(provider), fixture())
        self.assertEqual(result.findings, ())
        self.assertEqual([req.role for req in provider.requests],
                         [ModelRole.REPORT_SYNTHESIZER])
        report = user_payload(provider.requests[0])
        self.assertEqual(report["target"], "No reviewed findings")
        self.assertEqual(report["coverage_counts"], {})
        self.assertEqual(report["findings"], [])

    def test_reject_unexpected_pipeline_type_before_input_consult(self):
        data = fixture(fixture_finding())
        original = copy.deepcopy(data)
        with self.assertRaisesRegex(ValueError, "exact review pipeline"):
            review_admitted_remediation_batch(object(), data)
        self.assertEqual(data, original)

    def test_unbound_pipeline_never_dispatches(self):
        provider = RecordingScriptedProvider()
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(ModelRole.VERIFIER, provider.provider_id, "scripted-offline")
        with self.assertRaisesRegex(Exception, "no provider bound"):
            AssessmentReviewPipeline(gateway)
        self.assertEqual(provider.requests, [])


    def test_blank_advisor_output_fails_before_report_synthesis(self):
        provider = RecordingScriptedProvider()
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["  \t  "]
        with self.assertRaisesRegex(ValueError, "remediation_advisor"):
            review_admitted_remediation_batch(
                bound_pipeline(provider), fixture(fixture_finding())
            )
        self.assertEqual([r.role for r in provider.requests],
                         [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR])

    def test_invalid_verifier_status_fails_before_advisor_request(self):
        provider = RecordingScriptedProvider()
        provider._script[ModelRole.VERIFIER] = ["APPROVED and closed"]
        with self.assertRaisesRegex(ValueError, "verifier verdict"):
            review_admitted_remediation_batch(
                bound_pipeline(provider), fixture(fixture_finding())
            )
        self.assertEqual([r.role for r in provider.requests], [ModelRole.VERIFIER])

    def test_bad_output_unicode_surrogate_fails_before_report(self):
        provider = RecordingScriptedProvider()
        provider._script[ModelRole.REMEDIATION_ADVISOR] = ["invalid\ud800content"]
        with self.assertRaisesRegex(ValueError, "remediation_advisor"):
            review_admitted_remediation_batch(
                bound_pipeline(provider), fixture(fixture_finding())
            )
        self.assertEqual([r.role for r in provider.requests],
                         [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR])

    def test_blank_report_output_fails_closed(self):
        provider = RecordingScriptedProvider()
        provider._script[ModelRole.REPORT_SYNTHESIZER] = [""]
        with self.assertRaisesRegex(ValueError, "report_synthesizer"):
            review_admitted_remediation_batch(
                bound_pipeline(provider), fixture(fixture_finding())
            )
        self.assertEqual(provider.requests[-1].role, ModelRole.REPORT_SYNTHESIZER)

    def test_response_role_spoofing_is_rejected_before_advice(self):
        class WrongRoleProvider(RecordingScriptedProvider):
            def complete(self, request):
                original = super().complete(request)
                if request.role is ModelRole.VERIFIER:
                    return ModelResponse(
                        provider_id=original.provider_id,
                        model_id=original.model_id,
                        role=ModelRole.PLANNER,
                        content=original.content,
                    )
                return original
        provider = WrongRoleProvider()
        with self.assertRaisesRegex(ValueError, "wrong role"):
            review_admitted_remediation_batch(
                bound_pipeline(provider), fixture(fixture_finding())
            )
        self.assertEqual([r.role for r in provider.requests], [ModelRole.VERIFIER])

    def test_advisor_carries_exact_verifier_verdict_and_evidence_summary(self):
        provider = RecordingScriptedProvider()
        review_admitted_remediation_batch(bound_pipeline(provider),
                                          fixture(fixture_finding()))
        advisor = user_payload(provider.requests[1])
        verifier = user_payload(provider.requests[0])
        self.assertEqual(advisor["verifier_verdict"],
                         "UNCERTAIN synthetic evidence needs verification")
        self.assertEqual(advisor["evidence_summary"], verifier["evidence_summary"])
        self.assertEqual(advisor["evidence_ids"], verifier["evidence_ids"])
        self.assertEqual(advisor["target"], verifier["target"])
        report = user_payload(provider.requests[2])
        self.assertEqual(report["findings"][0]["verdict"],
                         "UNCERTAIN synthetic evidence needs verification")


if __name__ == "__main__":
    unittest.main()
