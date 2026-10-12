"""W30 regression: bounded synthetic Markdown evidence inputs, no target access."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_evidence_markdown_bounded_optin_w30 import (
    render_bounded_findings_markdown,
)
from lightup.finding_evidence_markdown_checked_optin_w28 import (
    render_checked_findings_markdown,
)
from lightup.models import Finding, RetestStatus, Severity


class BoundedMarkdownEvidenceW30Tests(unittest.TestCase):
    def finding(self, number=1, evidence=None, remediation="Fix locally"):
        return Finding(
            finding_id=f"synthetic:{number}",
            title="W30 synthetic test",
            severity=Severity.MEDIUM,
            target="offline.synthetic",
            evidence=["ref:one"] if evidence is None else evidence,
            remediation=remediation,
            retest_status=RetestStatus.NOT_TESTED,
        )

    def _assert_atomic_denial(self, findings):
        with patch(
            "lightup.finding_evidence_markdown_bounded_optin_w30."
            "render_checked_findings_markdown"
        ) as renderer:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_bounded_findings_markdown(findings)
            renderer.assert_not_called()

    def test_positive_renderer_keeps_evidence_order_and_multilingual_text(self):
        item = self.finding(evidence=["référence:é", "例:二", "ref:emoji-✈\ufe0f"])
        out = render_bounded_findings_markdown([item])
        self.assertLess(out.index("référence:é"), out.index("例:二"))
        self.assertIn("ref:emoji-✈\ufe0f", out)
        self.assertEqual(item.evidence, ["référence:é", "例:二", "ref:emoji-✈\ufe0f"])

    def test_empty_manual_evidence_and_empty_batch_retain_baseline(self):
        self.assertIn("No evidence recorded.", render_bounded_findings_markdown(
            [self.finding(evidence=[])]
        ))
        self.assertIn("No findings recorded.", render_bounded_findings_markdown([]))

    def test_per_reference_utf8_byte_ceiling_not_codepoint_count(self):
        valid = self.finding(evidence=["é" * 2048])
        self.assertIn("é" * 2048, render_bounded_findings_markdown([valid]))
        too_long = self.finding(evidence=["é" * 2049])
        self._assert_atomic_denial([too_long])
        self.assertEqual(too_long.evidence, ["é" * 2049])

    def test_per_displayed_field_ceiling(self):
        for field in ("finding_id", "title", "target", "remediation"):
            with self.subTest(field=field):
                item = self.finding()
                setattr(item, field, "x" * 16385)
                self._assert_atomic_denial([item])

    def test_total_batch_budget_denies_late_finding_before_rendering(self):
        findings = [
            self.finding(number=i, remediation="x" * 15000)
            for i in range(70)
        ]
        self._assert_atomic_denial(findings)
        self.assertEqual(findings[-1].remediation, "x" * 15000)

    def test_malformed_type_and_surrogate_are_generic_denial(self):
        class StrSubclass(str):
            pass

        for bad in (None, b"binary", StrSubclass("ref"), "\ud800", "", "  "):
            with self.subTest(value=repr(bad)):
                self._assert_atomic_denial([self.finding(evidence=["valid", bad])])

    def test_invalid_finding_and_evidence_containers_fail(self):
        class ListSubclass(list):
            pass

        for invalid in (None, (self.finding(),), ListSubclass([self.finding()])):
            self._assert_atomic_denial(invalid)
        for evidence in (None, ("ref:x",), ListSubclass(["ref:x"]), "ref:x"):
            self._assert_atomic_denial([self.finding(evidence=evidence)])

    def test_invalid_enum_and_late_invalid_ref_deny_entire_batch(self):
        item = self.finding()
        item.retest_status = "fixed"
        self._assert_atomic_denial([item])
        good = self.finding()
        bad = self.finding(2, evidence=["valid", "y" * 4097])
        self._assert_atomic_denial([good, bad])
        self.assertEqual(good.evidence, ["ref:one"])

    def test_snapshots_detach_metadata_and_caller_mutation(self):
        original = self.finding(evidence=["ref:stable"])
        original.metadata["secret"] = "synthetic-only"

        def observe(snapshots):
            self.assertIsNot(snapshots[0], original)
            self.assertIsNot(snapshots[0].evidence, original.evidence)
            self.assertEqual(snapshots[0].metadata, {})
            original.evidence[0] = "ref:changed"
            original.title = "changed title"
            return render_checked_findings_markdown(snapshots)

        with patch(
            "lightup.finding_evidence_markdown_bounded_optin_w30."
            "render_checked_findings_markdown", side_effect=observe
        ):
            output = render_bounded_findings_markdown([original])
        self.assertIn("- ref:stable", output)
        self.assertNotIn("ref:changed", output)
        self.assertNotIn("secret", output)

    def test_w28_control_remains_unbounded(self):
        huge = self.finding(evidence=["z" * 4097])
        self.assertIn("z" * 4097, render_checked_findings_markdown([huge]))
        self._assert_atomic_denial([huge])


if __name__ == "__main__":
    unittest.main()
