"""W43 in-memory report lineage cardinality acceptance, no target/network."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_markdown_escaped_optin_w31 import (
    render_escaped_evidence_markdown_optin_w31,
)
from lightup.models import Finding, RetestStatus, Severity


class MarkdownFindingLineageCardinalityW43(unittest.TestCase):
    def sample(self, suffix="one"):
        return Finding(
            finding_id="synthetic:" + suffix,
            title="Synthetic finding " + suffix,
            severity=Severity.LOW,
            target="offline.synthetic",
            evidence=["evidence:" + suffix + ":a", "evidence:" + suffix + ":b"],
            remediation="Manual review of synthetic " + suffix,
            retest_status=RetestStatus.NOT_TESTED,
        )

    def test_distinct_findings_and_ordered_distinct_evidence_are_retained(self):
        a, b = self.sample("one"), self.sample("two")
        rendered = render_escaped_evidence_markdown_optin_w31([a, b])
        self.assertLess(rendered.index("Synthetic finding one"), rendered.index("Synthetic finding two"))
        self.assertLess(rendered.index(r"evidence\:one\:a"), rendered.index(r"evidence\:one\:b"))
        self.assertEqual(a.evidence, ["evidence:one:a", "evidence:one:b"])

    def test_duplicate_finding_identity_is_atomic_denial(self):
        first, last = self.sample("one"), self.sample("one")
        last.title = "Different title but SAME finding identity"
        before = (first.finding_id, last.finding_id, tuple(first.evidence), tuple(last.evidence))
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as render:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([first, last])
            render.assert_not_called()
        self.assertEqual(
            (first.finding_id, last.finding_id, tuple(first.evidence), tuple(last.evidence)),
            before,
        )

    def test_duplicate_evidence_inside_last_finding_never_emits_partial_output(self):
        first = self.sample("one")
        last = self.sample("two")
        last.evidence = ["evidence:repeat", "evidence:repeat"]
        before = (tuple(first.evidence), tuple(last.evidence))
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as render:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([first, last])
            render.assert_not_called()
        self.assertEqual((tuple(first.evidence), tuple(last.evidence)), before)

    def test_same_evidence_reference_across_distinct_findings_is_permitted(self):
        first, second = self.sample("one"), self.sample("two")
        first.evidence = ["shared:evidence"]
        second.evidence = ["shared:evidence"]
        result = render_escaped_evidence_markdown_optin_w31([first, second])
        self.assertEqual(result.count(r"shared\:evidence"), 2)

    def test_identical_evidence_in_same_finding_denied_without_mutating_metadata(self):
        finding = self.sample()
        finding.evidence = ["evidence:one", "evidence:one"]
        finding.metadata["inert"] = "unexported"
        before = (tuple(finding.evidence), dict(finding.metadata))
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31([finding])
        self.assertEqual((tuple(finding.evidence), finding.metadata), before)

    def test_canonical_empty_evidence_compatibility(self):
        finding = self.sample()
        finding.evidence = []
        result = render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn("- No evidence recorded.", result)

    def test_original_lexical_identity_does_not_normalize_unicode(self):
        a, b = self.sample("é"), self.sample("e\u0301")
        a.evidence, b.evidence = ["id:é"], ["id:e\u0301"]
        result = render_escaped_evidence_markdown_optin_w31([a, b])
        self.assertIn("Synthetic finding é", result)
        self.assertIn("Synthetic finding e\u0301", result)
        self.assertEqual(a.finding_id, "synthetic:é")
        self.assertEqual(b.finding_id, "synthetic:e\u0301")

    def test_early_duplicate_does_not_hide_late_invalid_evidence(self):
        a, b, c = self.sample("one"), self.sample("one"), self.sample("three")
        c.evidence.append("ref:\u034finvalid")
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as render:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([a, b, c])
            render.assert_not_called()

    def test_compatibility_duplicate_preflight_does_not_authorize_retest(self):
        f = self.sample()
        f.retest_status = RetestStatus.FIXED
        f.evidence = ["evidence:same", "evidence:same"]
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31([f])
        self.assertEqual(f.retest_status, RetestStatus.FIXED)


if __name__ == "__main__":
    unittest.main()
