"""W28 opt-in Markdown evidence integrity checks, synthetic in-memory only."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_evidence_markdown_checked_optin_w28 import (
    render_checked_findings_markdown,
)
from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class FindingMarkdownEvidenceW28Tests(unittest.TestCase):
    def finding(self, evidence=None):
        return Finding(
            finding_id="synthetic:one",
            title="Synthetic finding",
            severity=Severity.MEDIUM,
            target="offline.synthetic",
            evidence=["evidence:one"] if evidence is None else evidence,
            remediation="Fix in a disposable offline lab",
            retest_status=RetestStatus.NOT_TESTED,
        )

    def test_canonical_evidence_renders_preserving_order(self):
        a = self.finding(["evidence:é", "evidence:two"])
        output = render_checked_findings_markdown([a])
        self.assertLess(output.index("- evidence:é"), output.index("- evidence:two"))
        self.assertIn("## Synthetic finding", output)
        self.assertEqual(a.evidence, ["evidence:é", "evidence:two"])

    def test_canonical_empty_legacy_evidence_keeps_fallback(self):
        result = render_checked_findings_markdown([self.finding([])])
        self.assertIn("No evidence recorded.", result)

    def test_malformed_container_denied_before_reporting(self):
        class ListSubclass(list):
            pass

        for value in (ListSubclass(["good"]), (), ("good",), "good", None, {}, b"x"):
            with self.subTest(shape=repr(value)):
                bad = self.finding()
                bad.evidence = value
                with patch(
                    "lightup.finding_evidence_markdown_checked_optin_w28.render_markdown"
                ) as writer:
                    with self.assertRaisesRegex(ValueError, "evidence integrity"):
                        render_checked_findings_markdown([bad])
                    writer.assert_not_called()

    def test_malformed_item_denied_before_reporting(self):
        class StrSubclass(str):
            pass

        for value in (StrSubclass("synthetic"), None, True, 7, b"x", "", "  ", {}):
            with self.subTest(value=repr(value)):
                evidence = ["valid", value]
                finding = self.finding(evidence)
                with patch(
                    "lightup.finding_evidence_markdown_checked_optin_w28.render_markdown"
                ) as writer:
                    with self.assertRaisesRegex(ValueError, "evidence integrity"):
                        render_checked_findings_markdown([finding])
                    writer.assert_not_called()
                self.assertIs(finding.evidence, evidence)

    def test_late_bad_evidence_prevents_all_report_emission(self):
        good = self.finding(["good"])
        bad = self.finding(["bad", " "])
        bad.finding_id = "synthetic:two"
        with patch(
            "lightup.finding_evidence_markdown_checked_optin_w28.render_markdown"
        ) as writer:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_checked_findings_markdown([good, bad])
            writer.assert_not_called()
        self.assertEqual(good.evidence, ["good"])
        self.assertEqual(bad.evidence, ["bad", " "])

    def test_snapshots_detach_original_list_and_omit_metadata(self):
        finding = self.finding(["original-evidence"])
        finding.metadata["unexported-secret"] = "synthetic-only"
        def observe(snapshots):
            self.assertIsNot(snapshots[0], finding)
            self.assertIsNot(snapshots[0].evidence, finding.evidence)
            self.assertEqual(snapshots[0].metadata, {})
            finding.evidence[0] = "changed-after-preflight"
            self.assertEqual(snapshots[0].evidence, ["original-evidence"])
            return render_markdown(snapshots)

        with patch(
            "lightup.finding_evidence_markdown_checked_optin_w28.render_markdown",
            side_effect=observe,
        ):
            output = render_checked_findings_markdown([finding])
        self.assertIn("- original-evidence", output)
        self.assertNotIn("changed-after-preflight", output)
        self.assertNotIn("unexported-secret", output)

    def test_invalid_batch_and_polymorphic_finding_denied(self):
        class FindingSubclass(Finding):
            pass

        original = self.finding()
        copy = FindingSubclass(**vars(original))
        for value in ((), None, "bad", [copy], [original] * 129):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    render_checked_findings_markdown(value)

    def test_existing_default_legacy_renderer_is_explicitly_not_repaired(self):
        malformed = self.finding([12345])
        legacy = render_markdown([malformed])
        self.assertIn("- 12345", legacy)
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_checked_findings_markdown([malformed])


if __name__ == "__main__":
    unittest.main()
