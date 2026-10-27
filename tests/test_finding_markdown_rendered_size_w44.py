"""W44 bounded rendered-Markdown acceptance; synthetic Unicode-free offline fixtures."""
from __future__ import annotations

import unittest

from lightup.finding_markdown_escaped_optin_w31 import (
    render_escaped_evidence_markdown_optin_w31,
)
from lightup.models import Finding, RetestStatus, Severity

_LIMIT = 2_097_152


class MarkdownRenderedOutputBudgetW44(unittest.TestCase):
    def batch(self, count, per_finding, quote_count):
        result = []
        for index in range(count):
            evidence = [
                "ref:" + str(i) + ":" + '"' * quote_count
                for i in range(per_finding)
            ]
            result.append(
                Finding(
                    finding_id="synthetic:batch-" + str(index),
                    title="Synthetic " + str(index),
                    severity=Severity.INFO,
                    target="offline.synthetic",
                    evidence=evidence,
                    remediation="Human review only",
                    retest_status=RetestStatus.NOT_TESTED,
                    metadata={"ignored": "synthetic-unexported"},
                )
            )
        return result

    def test_normal_escaped_batch_has_bounded_utf8_output(self):
        findings = self.batch(30, 100, 50)
        output = render_escaped_evidence_markdown_optin_w31(findings)
        self.assertLess(len(output.encode("utf-8")), _LIMIT)
        self.assertIn("&quot;", output)
        self.assertNotIn("synthetic-unexported", output)
        self.assertEqual(len(findings[0].evidence), 100)

    def test_html_entity_expansion_over_limit_fails_closed(self):
        findings = self.batch(64, 100, 80)
        # Raw source inputs stay under the existing 1 MiB admission budget.
        source = sum(
            len(value.encode("utf-8"))
            for finding in findings
            for value in (
                finding.finding_id, finding.title, finding.target,
                finding.remediation, *finding.evidence
            )
        )
        self.assertLess(source, 1_048_576)
        self.assertGreater(64 * 100 * 80 * 6, _LIMIT)
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31(findings)

    def test_overflow_denial_keeps_all_caller_data_unmodified(self):
        findings = self.batch(64, 100, 80)
        before = (
            tuple(findings[0].evidence),
            tuple(findings[-1].evidence),
            dict(findings[-1].metadata),
        )
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31(findings)
        self.assertEqual(
            (
                tuple(findings[0].evidence),
                tuple(findings[-1].evidence),
                findings[-1].metadata,
            ),
            before,
        )

    def test_existing_empty_report_still_returns_document(self):
        output = render_escaped_evidence_markdown_optin_w31([])
        self.assertEqual(
            output, "# LightUp Assessment Findings\n\nNo findings recorded.\n"
        )
        self.assertLess(len(output.encode("utf-8")), _LIMIT)

    def test_international_unicode_counts_encoded_bytes(self):
        one = self.batch(1, 2, 1)
        one[0].title = "Café résumé"
        one[0].evidence = ["ref:évidence", "ref:🔒\ufe0f"]
        result = render_escaped_evidence_markdown_optin_w31(one)
        self.assertIn("Café résumé", result)
        self.assertIn("🔒\ufe0f", result)
        self.assertLess(len(result.encode("utf-8")), _LIMIT)


if __name__ == "__main__":
    unittest.main()
