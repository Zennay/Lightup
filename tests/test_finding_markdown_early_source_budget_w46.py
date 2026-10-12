"""W46: offline preflight bounds for uninstalled escaped Finding Markdown."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


class MarkdownEarlySourceByteBudgetW46(unittest.TestCase):
    def finding(self, suffix="one"):
        return Finding(
            finding_id="synthetic:" + suffix,
            title="Synthetic " + suffix,
            severity=Severity.INFO,
            target="offline.synthetic",
            evidence=["ref:a", "ref:b"],
            remediation="Review offline evidence",
            retest_status=RetestStatus.NOT_TESTED,
            metadata={"inert": "not displayed"},
        )

    def test_huge_field_rejected_without_unicode_walk_or_render(self):
        finding = self.finding()
        finding.title = "a" * 1_000_000
        # Verify the oversized scalar itself fails before any Unicode walk;
        # normal preceding fields legitimately need their usual Unicode scan.
        with patch.object(renderer.unicodedata, "category", side_effect=AssertionError("walked huge field")) as category:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer._checked_literal(finding.title)
            category.assert_not_called()
        with patch.object(renderer, "_escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([finding])
            escape.assert_not_called()
        self.assertEqual(len(finding.title), 1_000_000)

    def test_exact_codepoint_limit_and_unicode_byte_boundary(self):
        self.assertEqual(renderer._checked_literal("a" * 16_384), ("a" * 16_384, 16_384))
        self.assertEqual(renderer._checked_literal("é" * 8192), ("é" * 8192, 16_384))
        for rejected in ("a" * 16_385, "é" * 8193, "☃" * 8192):
            with self.subTest(prefix=rejected[:1], length=len(rejected)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer._checked_literal(rejected)

    def test_noncanonical_and_whitespace_scalar_remain_denied(self):
        class UntrustedStr(str):
            pass
        for rejected in (UntrustedStr("valid"), " " * 16_384, "\t", "\ud800", 4):
            with self.subTest(repr=repr(rejected)[:30]):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer._checked_literal(rejected)

    def test_exact_cumulative_budget_stays_valid_and_one_byte_over_denies(self):
        finding = self.finding()
        total = sum(len(value.encode("utf-8")) for value in (
            finding.finding_id, finding.title, finding.target, finding.remediation,
            *finding.evidence
        ))
        with patch.object(renderer, "_MAX_BATCH_BYTES", total):
            expected = renderer.render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn(r"ref\:a", expected)
        with patch.object(renderer, "_MAX_BATCH_BYTES", total - 1):
            with patch.object(renderer, "_escape_literal") as escape:
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer.render_escaped_evidence_markdown_optin_w31([finding])
                escape.assert_not_called()
        self.assertEqual(finding.evidence, ["ref:a", "ref:b"])

    def test_overflow_aborts_before_validating_later_evidence(self):
        finding = self.finding()
        finding.evidence = [
            "ref:%03d:" % index + "x" * 9000 for index in range(128)
        ]
        before = (tuple(finding.evidence), dict(finding.metadata))
        with patch.object(renderer, "_checked_literal", wraps=renderer._checked_literal) as check:
            with patch.object(renderer, "_escape_literal") as escape:
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer.render_escaped_evidence_markdown_optin_w31([finding])
                escape.assert_not_called()
                self.assertLess(check.call_count, len(finding.evidence) + 4)
        self.assertEqual((tuple(finding.evidence), finding.metadata), before)

    def test_late_oversized_field_preflight_is_atomic(self):
        early, late = self.finding("early"), self.finding("late")
        late.evidence.append("z" * 1_000_000)
        original = tuple(late.evidence)
        with patch.object(renderer, "_escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([early, late])
            escape.assert_not_called()
        self.assertEqual(tuple(late.evidence), original)

    def test_normal_unicode_order_and_empty_fallback_unchanged(self):
        first = self.finding()
        first.title = "Résumé café"
        first.evidence = ["ref:é", "ref:🔒\ufe0f"]
        text = renderer.render_escaped_evidence_markdown_optin_w31([first])
        self.assertLess(text.index(r"ref\:é"), text.index(r"ref\:🔒"))
        self.assertNotIn("not displayed", text)
        self.assertEqual(
            renderer.render_escaped_evidence_markdown_optin_w31([]),
            "# LightUp Assessment Findings\n\nNo findings recorded.\n",
        )


if __name__ == "__main__":
    unittest.main()
