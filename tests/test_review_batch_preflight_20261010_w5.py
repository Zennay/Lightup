"""Disposable, network-free integration for the opt-in review admission sidecar.

The preflighted wrapper is a working optional path; the canonical pipeline
remains unchanged and the separate original-entrypoint RED tests remain RED.
"""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import (
    ModelGateway, ModelRequest, ModelResponse, ModelRole, ScriptedProvider,
)
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.review_batch_preflight import (
    preflight_review_batch, review_with_batch_preflight,
)


class RecordingProvider(ScriptedProvider):
    def __init__(self):
        super().__init__("offline-batch-preflight", {
            ModelRole.VERIFIER: ["UNCERTAIN synthetic observation"],
            ModelRole.REMEDIATION_ADVISOR: ["Synthetic fix review, no action."],
            ModelRole.REPORT_SYNTHESIZER: ["Synthetic report."],
        })
        self.requests: list[ModelRequest] = []

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return super().complete(request)


def _pipeline():
    provider = RecordingProvider()
    gateway = ModelGateway()
    gateway.register_provider(provider)
    for role in AssessmentReviewPipeline.ROLES:
        gateway.bind_role(role, provider.provider_id, "offline-fixture")
    return AssessmentReviewPipeline(gateway), provider


def _source() -> dict:
    return {
        "target": "http://127.0.0.1:18080/",
        "findings": [{
            "finding": "Synthetic missing header",
            "severity": "medium",
            "impact": "No real impact claimed",
            "fix": "  Configure test-only header  ",
            "evidence_ids": ["ev:1", "ev:2"],
            "evidence_summary": "Two fabricated observations.",
            "target": "http://127.0.0.1:18080/test",
            "raw_evidence_payload": "DO_NOT_FORWARD",
        }],
        "coverage": {"counts": {"assessed": 1, "unknown": 5}},
        "authorization_grant": "UNTRUSTED",
    }


class ReviewBatchPreflightTest(unittest.TestCase):
    def _deny_before_model(self, mutation):
        source = _source()
        mutation(source)
        untouched = copy.deepcopy(source)
        pipeline, provider = _pipeline()
        with self.assertRaises(ValueError):
            review_with_batch_preflight(pipeline, source)
        self.assertEqual(provider.requests, [])
        self.assertEqual(source, untouched)

    def test_full_valid_review_remains_ordered(self):
        source = _source()
        untouched = copy.deepcopy(source)
        pipeline, provider = _pipeline()
        result = review_with_batch_preflight(pipeline, source)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(source, untouched)
        self.assertEqual(tuple(req.role for req in provider.requests), (
            ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
            ModelRole.REPORT_SYNTHESIZER,
        ))
        self.assertNotIn("DO_NOT_FORWARD", repr(provider.requests))
        self.assertNotIn("UNTRUSTED", repr(provider.requests))
        self.assertIn("  Configure test-only header  ", repr(provider.requests[1]))

    def test_snapshot_has_detached_lists_and_drops_unknowns(self):
        original = _source()
        detached = preflight_review_batch(original)
        self.assertNotIn("authorization_grant", detached)
        self.assertNotIn("raw_evidence_payload", detached["findings"][0])
        original["findings"][0]["evidence_ids"].append("ev:3")
        original["findings"][0]["fix"] = "spoof later"
        original["coverage"]["counts"]["assessed"] = 400
        self.assertEqual(detached["findings"][0]["evidence_ids"], ["ev:1", "ev:2"])
        self.assertEqual(detached["findings"][0]["fix"], "  Configure test-only header  ")
        self.assertEqual(detached["coverage"]["counts"]["assessed"], 1)

    def test_second_finding_duplicate_refs_has_zero_requests(self):
        def mutation(source):
            second = copy.deepcopy(source["findings"][0])
            second["evidence_ids"] = ["ev:3", "ev:3"]
            source["findings"].append(second)
        self._deny_before_model(mutation)

    def test_second_finding_invalid_fix_has_zero_requests(self):
        def mutation(source):
            second = copy.deepcopy(source["findings"][0])
            second["fix"] = " \t "
            source["findings"].append(second)
        self._deny_before_model(mutation)

    def test_second_finding_bad_evidence_summary_has_zero_requests(self):
        def mutation(source):
            second = copy.deepcopy(source["findings"][0])
            second["evidence_summary"] = " \n "
            source["findings"].append(second)
        self._deny_before_model(mutation)

    def test_bad_first_finding_fix_has_zero_requests(self):
        self._deny_before_model(lambda s: s["findings"][0].update(fix=""))

    def test_non_string_fix_denies(self):
        for value in (None, True, 33, b"fix", ["fix"]):
            with self.subTest(value=value):
                self._deny_before_model(lambda s, v=value: s["findings"][0].update(fix=v))

    def test_fix_subclass_denies_without_string_callback(self):
        class Trick(str):
            def __str__(self):
                raise AssertionError("untrusted str callback")
        self._deny_before_model(
            lambda s: s["findings"][0].update(fix=Trick("spoof"))
        )

    def test_evidence_duplicates_denied_no_repair(self):
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_ids=["ev:1", "ev:1"])
        )

    def test_reference_subclass_and_wrong_container_denied(self):
        class Trick(str):
            def __str__(self):
                raise AssertionError("untrusted str callback")
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_ids=["ev:1", Trick("ev:2")])
        )
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_ids=("ev:1", "ev:2"))
        )

    def test_explicit_empty_evidence_not_masked_by_fallback(self):
        def mutation(s):
            s["evidence_id"] = "legacy:valid"
            s["findings"][0]["evidence_ids"] = []
        self._deny_before_model(mutation)

    def test_legacy_single_ref_fallback_remains_valid(self):
        source = _source()
        source["evidence_id"] = "legacy:single"
        del source["findings"][0]["evidence_ids"]
        snapshot = preflight_review_batch(source)
        self.assertEqual(snapshot["findings"][0]["evidence_ids"], ["legacy:single"])
        pipeline, provider = _pipeline()
        result = review_with_batch_preflight(pipeline, source)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(provider.requests), 3)

    def test_legacy_null_ref_fallback_remains_valid(self):
        source = _source()
        source["evidence_id"] = "legacy:single"
        source["findings"][0]["evidence_ids"] = None
        snapshot = preflight_review_batch(source)
        self.assertEqual(snapshot["findings"][0]["evidence_ids"], ["legacy:single"])

    def test_missing_evidence_and_bad_top_level_fallback_denied(self):
        self._deny_before_model(
            lambda s: s["findings"][0].pop("evidence_ids")
        )
        def mutation(s):
            del s["findings"][0]["evidence_ids"]
            s["evidence_id"] = 77
        self._deny_before_model(mutation)

    def test_invalid_batch_and_findings_type_denied(self):
        for value in (None, 9, (), {}):
            with self.subTest(value=value):
                pipeline, provider = _pipeline()
                with self.assertRaises(ValueError):
                    review_with_batch_preflight(pipeline, value)
                self.assertEqual(provider.requests, [])
        self._deny_before_model(lambda s: s.update(findings=tuple(s["findings"])))

    def test_oversize_batch_fails_before_provider(self):
        self._deny_before_model(
            lambda s: s.update(findings=s["findings"] * 129)
        )

    def test_oversize_refs_fail_before_provider(self):
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_ids=["ev:%d" % x for x in range(65)])
        )
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_ids=["e"*257])
        )

    def test_long_fix_and_summary_denied(self):
        self._deny_before_model(
            lambda s: s["findings"][0].update(fix="x"*8193)
        )
        self._deny_before_model(
            lambda s: s["findings"][0].update(evidence_summary="x"*4097)
        )

    def test_bad_unknown_provider_metadata_not_forwarded(self):
        source = _source()
        source["findings"][0]["authorization_grant"] = "DO_NOT_FORWARD_TOKEN"
        pipeline, provider = _pipeline()
        review_with_batch_preflight(pipeline, source)
        self.assertNotIn("DO_NOT_FORWARD_TOKEN", repr(provider.requests))

    def test_bad_coverage_types_fail_before_provider(self):
        self._deny_before_model(
            lambda s: s.update(coverage={"counts": {"assessed": True}})
        )
        self._deny_before_model(
            lambda s: s.update(coverage={"counts": {"assessed": -1}})
        )
        self._deny_before_model(
            lambda s: s.update(coverage={"counts": ["assessed"]})
        )

    def test_unsafe_key_subclasses_fail_before_provider(self):
        class Key(str):
            pass
        self._deny_before_model(
            lambda s: s["findings"][0].update({Key("spoof"): "x"})
        )

    def test_untrusted_finding_object_does_not_call_callbacks(self):
        class Hostile(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("must never invoke hostile get")
        self._deny_before_model(
            lambda s: s.update(findings=[Hostile(s["findings"][0])])
        )

    def test_pipeline_wrong_type_denied_pre_provider(self):
        pipeline, provider = _pipeline()
        class Pretender(AssessmentReviewPipeline):
            pass
        # Plain object cannot become a trusted ModelGateway wrapper.
        with self.assertRaises(ValueError):
            review_with_batch_preflight(object(), _source())
        self.assertEqual(provider.requests, [])

    def test_zero_findings_report_is_not_security_approval(self):
        source = _source()
        source["findings"] = []
        pipeline, provider = _pipeline()
        result = review_with_batch_preflight(pipeline, source)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(provider.requests), 1)
        self.assertEqual(provider.requests[0].role, ModelRole.REPORT_SYNTHESIZER)


if __name__ == "__main__":
    unittest.main()
