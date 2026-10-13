"""Offline-only, deterministic opt-in remediation input preflight regressions.

No provider, gateway, HTTP, SQLite or target access. The source is an additive
pure-function reference and is NOT wired into the installed review pipeline.
"""
from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError

from lightup.ai.remediation_input_preflight_optin import (
    MAX_BATCH_FIX_CHARS,
    MAX_CURRENT_FIX_CHARS,
    MAX_EVIDENCE_REF_CHARS,
    MAX_EVIDENCE_REFS,
    MAX_EVIDENCE_SUMMARY_CHARS,
    MAX_FINDINGS,
    PreparedRemediationBatch,
    prepare_remediation_review_inputs,
)


class StringSubclass(str):
    pass


class ListSubclass(list):
    pass


class DictSubclass(dict):
    pass


def finding(fix="  Enable CSP; test headers afterwards.  ", evidence_ids=None):
    return {
        "finding": "Synthetic CSP finding",
        "severity": "medium",
        "impact": "Synthetic impact",
        "target": "asset://offline",
        "fix": fix,
        "evidence_summary": "Synthetic summary; not verified evidence.",
        "evidence_ids": ["evidence:one", "evidence:two"] if evidence_ids is None else evidence_ids,
    }


def payload(*findings):
    return {"target": "asset://offline", "findings": list(findings)}


class OptionalRemediationInputPreflightTest(unittest.TestCase):
    def reject_unchanged(self, data, pattern="review input"):
        before = copy.deepcopy(data)
        with self.assertRaisesRegex(ValueError, pattern):
            prepare_remediation_review_inputs(data)
        self.assertEqual(data, before)

    def test_empty_batch_is_atomic_immutable_snapshot(self):
        result = prepare_remediation_review_inputs(payload())
        self.assertIs(type(result), PreparedRemediationBatch)
        self.assertEqual(result.findings, ())
        with self.assertRaises(FrozenInstanceError):
            result.findings = ()

    def test_canonical_fix_and_order_preserved_without_normalization(self):
        original = payload(
            finding("  Fix A  ", ["evidence:two", "evidence:one"]),
            finding("Fix B", ["evidence:three"]),
        )
        before = copy.deepcopy(original)
        batch = prepare_remediation_review_inputs(original)
        self.assertEqual(original, before)
        self.assertEqual([x.current_fix for x in batch.findings], ["  Fix A  ", "Fix B"])
        self.assertEqual(batch.findings[0].evidence_ids, ("evidence:two", "evidence:one"))
        self.assertEqual(batch.findings[1].evidence_ids, ("evidence:three",))
        self.assertEqual(batch.findings[0].evidence_summary,
                         "Synthetic summary; not verified evidence.")

    def test_result_does_not_alias_mutable_caller_evidence_container(self):
        data = payload(finding())
        batch = prepare_remediation_review_inputs(data)
        data["findings"][0]["evidence_ids"].append("evidence:later")
        data["findings"].clear()
        self.assertEqual(batch.findings[0].evidence_ids, ("evidence:one", "evidence:two"))
        self.assertEqual(len(batch.findings), 1)
        with self.assertRaises(FrozenInstanceError):
            batch.findings[0].current_fix = "modified"

    def test_legacy_evidence_fallback_with_absent_or_empty_local_refs(self):
        for item in (finding(), finding(evidence_ids=[])):
            item.pop("evidence_ids", None) if item["evidence_ids"] else None
            data = payload(item)
            data["evidence_id"] = "evidence:legacy"
            batch = prepare_remediation_review_inputs(data)
            self.assertEqual(batch.findings[0].evidence_ids, ("evidence:legacy",))
        explicit_empty = payload(finding(evidence_ids=[]))
        explicit_empty["evidence_id"] = "evidence:legacy"
        self.assertEqual(
            prepare_remediation_review_inputs(explicit_empty).findings[0].evidence_ids,
            ("evidence:legacy",),
        )

    def test_raw_payload_never_copied_to_prepared_metadata(self):
        data = payload(finding())
        data["findings"][0]["evidence_payload"] = "SYNTHETIC-RAW-SECRET"
        data["evidence_payload"] = "SYNTHETIC-RAW-SECRET"
        prepared = prepare_remediation_review_inputs(data)
        self.assertNotIn("SYNTHETIC-RAW-SECRET", repr(prepared))
        self.assertNotIn("evidence_payload", repr(prepared))

    def test_later_bad_finding_rejects_entire_batch(self):
        data = payload(finding("Valid"), finding(""))
        self.reject_unchanged(data, "remediation")

    def test_reject_bad_fix_values_without_coercion(self):
        for invalid in ("", "  \t\n", None, 12, False, [], {}, StringSubclass("valid")):
            with self.subTest(fix_type=type(invalid).__name__, fix=repr(invalid)):
                self.reject_unchanged(payload(finding(invalid)), "remediation")

    def test_max_fix_size_is_inclusive(self):
        self.assertEqual(
            len(prepare_remediation_review_inputs(
                payload(finding("X" * MAX_CURRENT_FIX_CHARS))
            ).findings[0].current_fix),
            MAX_CURRENT_FIX_CHARS,
        )
        self.reject_unchanged(payload(finding("X" * (MAX_CURRENT_FIX_CHARS + 1))),
                              "remediation")

    def test_global_fix_budget_rejects_even_individually_valid_items(self):
        n = MAX_BATCH_FIX_CHARS // MAX_CURRENT_FIX_CHARS + 1
        data = payload(*(finding("X" * MAX_CURRENT_FIX_CHARS) for _ in range(n)))
        self.reject_unchanged(data, "budget")

    def test_reject_duplicate_evidence_refs_without_silent_deduplication(self):
        self.reject_unchanged(
            payload(finding(evidence_ids=["evidence:one", "evidence:one"])),
            "duplicate",
        )

    def test_reject_wrong_evidence_container_and_item_types(self):
        bad_refs = (
            "evidence:one", ("evidence:one",), ListSubclass(["evidence:one"]),
            ["evidence:one", 2], ["evidence:one", False],
            [StringSubclass("evidence:one")], [""], ["  "],
        )
        for candidate in bad_refs:
            with self.subTest(candidate=repr(candidate)):
                self.reject_unchanged(payload(finding(evidence_ids=candidate)),
                                      "evidence")

    def test_reject_missing_evidence_even_with_valid_fix(self):
        self.reject_unchanged(payload(finding(evidence_ids=[])), "evidence")

    def test_reject_bad_legacy_evidence_identity(self):
        for legacy in ("", "   ", 7, None, StringSubclass("evidence:legacy")):
            with self.subTest(legacy=repr(legacy)):
                data = payload(finding(evidence_ids=[]))
                data["evidence_id"] = legacy
                self.reject_unchanged(data, "evidence")

    def test_duplicate_ids_across_distinct_findings_are_not_assumed_invalid(self):
        data = payload(finding("fix A", ["shared:id"]), finding("fix B", ["shared:id"]))
        result = prepare_remediation_review_inputs(data)
        self.assertEqual(result.findings[0].evidence_ids, ("shared:id",))
        self.assertEqual(result.findings[1].evidence_ids, ("shared:id",))

    def test_ref_count_and_character_boundaries(self):
        max_refs = [f"evidence:{i}" for i in range(MAX_EVIDENCE_REFS)]
        self.assertEqual(
            len(prepare_remediation_review_inputs(
                payload(finding(evidence_ids=max_refs))
            ).findings[0].evidence_ids),
            MAX_EVIDENCE_REFS,
        )
        self.reject_unchanged(
            payload(finding(evidence_ids=max_refs + ["evidence:extra"])), "too many"
        )
        self.assertEqual(
            len(prepare_remediation_review_inputs(
                payload(finding(evidence_ids=["E" * MAX_EVIDENCE_REF_CHARS]))
            ).findings[0].evidence_ids[0]),
            MAX_EVIDENCE_REF_CHARS,
        )
        self.reject_unchanged(
            payload(finding(evidence_ids=["E" * (MAX_EVIDENCE_REF_CHARS + 1)])),
            "evidence",
        )

    def test_max_batch_cardinality(self):
        exact = payload(*(finding(f"fix-{i}") for i in range(MAX_FINDINGS)))
        self.assertEqual(len(prepare_remediation_review_inputs(exact).findings),
                         MAX_FINDINGS)
        self.reject_unchanged(
            payload(*(finding(f"fix-{i}") for i in range(MAX_FINDINGS + 1))),
            "too many",
        )

    def test_bad_top_level_and_nested_shapes_reject_before_iterator_hooks(self):
        self.reject_unchanged([], "dictionary")
        self.reject_unchanged(DictSubclass(payload(finding())), "dictionary")
        self.reject_unchanged({"findings": ListSubclass([finding()])}, "exact list")
        self.reject_unchanged({"findings": (finding(),)}, "exact list")
        self.reject_unchanged(payload(DictSubclass(finding())), "exact dictionary")
        self.reject_unchanged({"findings": ["not-a-finding"]}, "exact dictionary")

    def test_reject_unbounded_or_invalid_summary(self):
        data = payload(finding())
        data["findings"][0]["evidence_summary"] = "x" * MAX_EVIDENCE_SUMMARY_CHARS
        self.assertEqual(len(
            prepare_remediation_review_inputs(data).findings[0].evidence_summary
        ), MAX_EVIDENCE_SUMMARY_CHARS)
        for invalid in ("", " ", "x" * (MAX_EVIDENCE_SUMMARY_CHARS + 1), 12):
            data = payload(finding())
            data["findings"][0]["evidence_summary"] = invalid
            self.reject_unchanged(data, "evidence summary")

    def test_invalid_critical_metadata_rejects_whole_batch(self):
        for field in ("finding", "severity", "impact", "target"):
            data = payload(finding("Valid fix"), finding("Valid fix"))
            data["findings"][1][field] = ""
            with self.subTest(field=field):
                self.reject_unchanged(data)

    def test_unicode_surrogates_are_refused_at_input(self):
        for key, value in (("fix", "hi\ud800"), ("evidence_summary", "x\udfff")):
            data = payload(finding())
            data["findings"][0][key] = value
            self.reject_unchanged(data, "surrogate")

    def test_no_authorizing_or_dispatch_capabilities_in_return_value(self):
        batch = prepare_remediation_review_inputs(payload(finding()))
        attrs = dir(batch)
        for forbidden in ("grant", "authorize", "execute", "verdict", "dispatch"):
            self.assertNotIn(forbidden, attrs)
        self.assertEqual(batch.findings[0].target, "asset://offline")


    def test_display_target_fallback_and_bound_preserve_only_label(self):
        item = finding()
        item.pop("target")
        data = payload(item)
        data["target"] = "asset://synthetic-fallback"
        prepared = prepare_remediation_review_inputs(data)
        self.assertEqual(prepared.findings[0].target, "asset://synthetic-fallback")
        data["target"] = ""
        self.reject_unchanged(data, "target")
        data["target"] = "x" * 1025
        self.reject_unchanged(data, "target")


if __name__ == "__main__":
    unittest.main()
