"""W29 conservative opt-in Markdown presentation admission, offline synthetic only."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_markdown_literal_gate_optin_w29 import (
    render_literal_checked_findings_markdown,
)
from lightup.finding_evidence_markdown_checked_optin_w28 import (
    render_checked_findings_markdown,
)
from lightup.models import Finding, RetestStatus, Severity


class LiteralMarkdownEvidenceTests(unittest.TestCase):
    def sample(self) -> Finding:
        return Finding(
            finding_id="lab:fixture-1",
            title="Cafe audit",
            severity=Severity.LOW,
            target="offline.synthetic",
            evidence=["ref:alpha-1", "ref:beta-2"],
            remediation="Replace a local configuration",
            retest_status=RetestStatus.NOT_TESTED,
        )

    def test_canonical_lines_and_international_letters(self):
        finding = self.sample()
        finding.title = "Café verificatie"
        finding.evidence = ["référence:alpha", "referentie:beta"]
        report = render_literal_checked_findings_markdown([finding])
        self.assertIn("## Café verificatie", report)
        self.assertLess(report.index("référence:alpha"), report.index("referentie:beta"))
        self.assertEqual(finding.evidence, ["référence:alpha", "referentie:beta"])

    def test_legacy_empty_evidence_remains_supported(self):
        finding = self.sample()
        finding.evidence = []
        self.assertIn("No evidence recorded.", render_literal_checked_findings_markdown([finding]))

    def test_untrusted_markdown_and_html_are_atomic_denials(self):
        malicious = (
            "<script>example</script>",
            "<img src=x>",
            "[external](https://invalid.example)",
            "**synthetic**",
            "`code`",
            "# Heading",
            "1. New section",
            "12) Another section",
            "text\\backslash",
            "a|b",
            "has_underscore",
            "x=1",
            "a&b",
            "one\n## Forged finding",
            "one\rreturn",
            "a\ttab",
        )
        for value in malicious:
            for field in ("finding_id", "title", "target", "remediation", "evidence"):
                with self.subTest(field=field, value=repr(value)):
                    original = self.sample()
                    if field == "evidence":
                        original.evidence = ["ref:valid", value]
                    else:
                        setattr(original, field, value)
                    with patch(
                        "lightup.finding_markdown_literal_gate_optin_w29.render_checked_findings_markdown"
                    ) as renderer:
                        with self.assertRaisesRegex(ValueError, "presentation integrity"):
                            render_literal_checked_findings_markdown([original])
                        renderer.assert_not_called()

    def test_unicode_compatibility_and_invisible_controls_rejected(self):
        for value in (
            "A\u202eB",  # bidi override
            "A\u200dB",  # zero width joiner
            "A\ufe0fB",  # variation selector
            "A\x00B",
            "A\uff1cb\uff1e",  # fullwidth angle brackets -> HTML syntax
            "A\uff3bb\uff3d",  # fullwidth Markdown link brackets
            "A\uff40B",  # fullwidth backtick
            "A\u2028B",  # Unicode line separator
            "\u0301A",  # leading combining mark
        ):
            with self.subTest(value=repr(value)):
                finding = self.sample()
                finding.remediation = value
                with self.assertRaisesRegex(ValueError, "presentation integrity"):
                    render_literal_checked_findings_markdown([finding])

    def test_late_row_refusal_does_not_emit_first_finding(self):
        earlier = self.sample()
        later = self.sample()
        later.finding_id = "lab:fixture-2"
        later.evidence = ["ref:valid", "bad\n# false finding"]
        with patch(
            "lightup.finding_markdown_literal_gate_optin_w29.render_checked_findings_markdown"
        ) as renderer:
            with self.assertRaisesRegex(ValueError, "presentation integrity"):
                render_literal_checked_findings_markdown([earlier, later])
            renderer.assert_not_called()
        self.assertEqual(earlier.evidence, ["ref:alpha-1", "ref:beta-2"])
        self.assertEqual(later.evidence[1], "bad\n# false finding")

    def test_snapshot_omits_metadata_and_is_independent_of_original(self):
        finding = self.sample()
        finding.metadata["private-key-name"] = "synthetic-not-secret"
        def observe(rows):
            self.assertIsNot(rows[0], finding)
            self.assertIsNot(rows[0].evidence, finding.evidence)
            self.assertEqual(rows[0].metadata, {})
            finding.evidence[0] = "mutated-after-validation"
            self.assertEqual(rows[0].evidence, ["ref:alpha-1", "ref:beta-2"])
            return render_checked_findings_markdown(rows)
        with patch(
            "lightup.finding_markdown_literal_gate_optin_w29.render_checked_findings_markdown",
            side_effect=observe,
        ):
            result = render_literal_checked_findings_markdown([finding])
        self.assertIn("ref:alpha-1", result)
        self.assertNotIn("synthetic-not-secret", result)
        self.assertNotIn("mutated-after-validation", result)

    def test_input_classes_and_lengths_fail_closed(self):
        class NotAPlainList(list):
            pass
        class NotAPlainString(str):
            pass
        canonical = self.sample()
        for rows in (None, (canonical,), NotAPlainList([canonical]), [canonical] * 129):
            with self.subTest(shape=repr(type(rows))):
                with self.assertRaisesRegex(ValueError, "presentation integrity"):
                    render_literal_checked_findings_markdown(rows)
        for evidence in (NotAPlainList(["ref:x"]), ["ref:x"] * 129, [NotAPlainString("x")], [123]):
            f = self.sample()
            f.evidence = evidence
            with self.subTest(evidence=repr(type(evidence))):
                with self.assertRaisesRegex(ValueError, "presentation integrity"):
                    render_literal_checked_findings_markdown([f])
        for value in ("X" * 1025, "  ", "   x", ".prefix", "0. paragraph"):
            f = self.sample()
            f.title = value
            with self.subTest(value=value[:16]):
                with self.assertRaisesRegex(ValueError, "presentation integrity"):
                    render_literal_checked_findings_markdown([f])

    def test_previous_opt_in_is_explicitly_not_protected(self):
        f = self.sample()
        f.remediation = "Fix\n## Forged separate section"
        self.assertIn("## Forged separate section", render_checked_findings_markdown([f]))
        with self.assertRaisesRegex(ValueError, "presentation integrity"):
            render_literal_checked_findings_markdown([f])

    def test_no_findings_is_existing_compatible_output(self):
        self.assertIn("No findings recorded.", render_literal_checked_findings_markdown([]))


if __name__ == "__main__":
    unittest.main()
