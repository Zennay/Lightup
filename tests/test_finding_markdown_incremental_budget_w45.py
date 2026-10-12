"""W45: synthetic offline acceptance for incremental escaped Markdown byte cap."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


class MarkdownIncrementalOutputBudgetW45(unittest.TestCase):
    def finding(self, suffix="one"):
        return Finding(
            finding_id="synthetic:" + suffix,
            title="Synthetic café " + suffix,
            severity=Severity.LOW,
            target="offline.synthetic",
            evidence=['ref:"quoted"&<html>', "ref:🔒\ufe0f"],
            remediation="Check the synthetic evidence only.",
            retest_status=RetestStatus.NOT_TESTED,
            metadata={"private": "excluded-synthetic-metadata"},
        )

    def test_output_equal_to_byte_ceiling_is_preserved(self):
        sample = self.finding()
        expected = renderer.render_escaped_evidence_markdown_optin_w31([sample])
        exact_size = len(expected.encode("utf-8"))
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", exact_size):
            self.assertEqual(
                renderer.render_escaped_evidence_markdown_optin_w31([sample]),
                expected,
            )
        self.assertIn("&quot;", expected)
        self.assertIn("&lt;html&gt;", expected)
        self.assertNotIn("excluded-synthetic-metadata", expected)

    def test_one_byte_below_cap_refuses_complete_report(self):
        sample = self.finding()
        expected = renderer.render_escaped_evidence_markdown_optin_w31([sample])
        before = (tuple(sample.evidence), dict(sample.metadata))
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", len(expected.encode("utf-8")) - 1):
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([sample])
        self.assertEqual((tuple(sample.evidence), sample.metadata), before)

    def test_budget_exhaustion_stops_before_escaping_later_findings(self):
        first, second = self.finding("first"), self.finding("second")
        allowed = renderer.render_escaped_evidence_markdown_optin_w31([first])
        budget = len(allowed.encode("utf-8")) - 1
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", budget):
            with patch.object(renderer, "_escape_literal", wraps=renderer._escape_literal) as escape:
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer.render_escaped_evidence_markdown_optin_w31([first, second])
                escaped_inputs = [call.args[0] for call in escape.call_args_list]
        self.assertNotIn(second.title, escaped_inputs)
        self.assertNotIn(second.finding_id, escaped_inputs)
        self.assertEqual(second.evidence[0], 'ref:"quoted"&<html>')

    def test_invalid_last_row_preflight_precedes_any_output_escaping(self):
        first, last = self.finding("first"), self.finding("last")
        last.evidence.append("ref:\u034finvalid")
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", 60):
            with patch.object(renderer, "_escape_literal") as escape:
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer.render_escaped_evidence_markdown_optin_w31([first, last])
                escape.assert_not_called()
        self.assertEqual(last.evidence[-1], "ref:\u034finvalid")

    def test_html_expansion_stops_before_escaping_all_large_evidence(self):
        sample = self.finding()
        sample.evidence = ["ref:%02d:" % index + '"' * 1000 for index in range(90)]
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", 15_000):
            with patch.object(renderer, "_escape_literal", wraps=renderer._escape_literal) as escape:
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer.render_escaped_evidence_markdown_optin_w31([sample])
                self.assertLess(escape.call_count, 20)
        self.assertEqual(len(sample.evidence), 90)

    def test_empty_batch_keeps_unmodified_fallback(self):
        self.assertEqual(
            renderer.render_escaped_evidence_markdown_optin_w31([]),
            "# LightUp Assessment Findings\n\nNo findings recorded.\n",
        )


if __name__ == "__main__":
    unittest.main()
