import unittest

from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class ReportingTests(unittest.TestCase):
    def test_empty_report_has_canonical_trailing_newline(self):
        self.assertEqual(
            render_markdown([]),
            "# LightUp Assessment Findings\n\nNo findings recorded.\n",
        )

    def test_finding_report_has_canonical_trailing_newline(self):
        finding = Finding(
            finding_id="finding-1",
            title="Missing security header",
            severity=Severity.MEDIUM,
            target="https://example.test/",
            evidence=["Content-Security-Policy is absent"],
            remediation="Add a restrictive Content-Security-Policy header.",
            retest_status=RetestStatus.FIX_PENDING,
        )

        report = render_markdown([finding])

        self.assertTrue(report.endswith("\n"))
        self.assertIn("## Missing security header", report)
        self.assertIn("- ID: `finding-1`", report)
        self.assertIn("- Target: `https://example.test/`", report)
        self.assertIn(
            "> Add a restrictive Content-Security-Policy header.",
            report,
        )

    def test_untrusted_text_cannot_break_report_structure_or_emit_raw_html(self):
        finding = Finding(
            finding_id="id`value\n## forged-id",
            title="Expected title\n## forged-title <script>",
            severity=Severity.HIGH,
            target="https://example.test/\n## forged-target",
            evidence=["Observed value\n## forged-evidence <img src=x onerror=1>"],
            remediation="Apply fix\n## forged-remediation\n<script>alert(1)</script>",
        )

        report = render_markdown([finding])

        self.assertEqual(report.count("\n## "), 1)
        self.assertEqual(report.count("\n### Evidence"), 1)
        self.assertEqual(report.count("\n### Remediation"), 1)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<img", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img src=x onerror=1&gt;", report)
        self.assertIn("## forged-id", report)
        self.assertIn("## forged-target", report)
        self.assertIn("> ## forged-remediation", report)
        self.assertTrue(report.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
