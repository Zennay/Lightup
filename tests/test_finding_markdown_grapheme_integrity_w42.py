"""W42 independent Markdown grapheme-admission regression, synthetic PLAN/LAB only."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_markdown_escaped_optin_w31 import (
    _checked_literal,
    render_escaped_evidence_markdown_optin_w31,
)
from lightup.models import Finding, RetestStatus, Severity


class MarkdownGraphemeIntegrityW42(unittest.TestCase):
    def fixture(self, suffix="1"):
        return Finding(
            finding_id="synthetic:fixture-" + suffix,
            title="Synthetic title",
            severity=Severity.LOW,
            target="offline.synthetic",
            evidence=["ref:fixture-" + suffix],
            remediation="Manual synthetic remediation",
            retest_status=RetestStatus.NOT_TESTED,
        )

    def test_punctuation_does_not_anchor_combining_mark(self):
        for text in (
            "ref:\u0301evidence", "ref/\u0301evidence", "ref.\u0301evidence",
            "ref-\u0301evidence", "ref(\u0301evidence",
            "ref_\ufe0fvalue", "ref@\ufe0fvalue", "ref#\u0301value",
        ):
            with self.subTest(text=repr(text)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    _checked_literal(text)

    def test_combining_grapheme_joiner_is_never_display_text(self):
        for text in (
            "a\u034fb", "synthetic:\u034fref", "\u034fleading",
            "synthetic a\u034f synthetic",
        ):
            with self.subTest(text=repr(text)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    _checked_literal(text)

    def test_ordinary_accented_unicode_and_emoji_mark_stay_accepted(self):
        values = (
            "Résumé évidence", "e\u0301vidence", "Evidence: résumé",
            "\u2728\ufe0f evidence", "🔒\ufe0f", "A\u0301/B",
        )
        for value in values:
            with self.subTest(value=repr(value)):
                returned, length = _checked_literal(value)
                self.assertEqual(returned, value)
                self.assertEqual(length, len(value.encode("utf-8")))

    def test_each_untrusted_display_field_refuses_ambiguous_marks(self):
        for name in ("finding_id", "title", "target", "remediation", "evidence"):
            with self.subTest(name=name):
                finding = self.fixture()
                raw = "synthetic:\u0301invisible"
                if name == "evidence":
                    finding.evidence.append(raw)
                else:
                    setattr(finding, name, raw)
                with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as renderer:
                    with self.assertRaisesRegex(ValueError, "evidence integrity"):
                        render_escaped_evidence_markdown_optin_w31([finding])
                    renderer.assert_not_called()

    def test_bad_last_row_is_atomic_and_caller_state_untouched(self):
        good = self.fixture()
        bad = self.fixture("2")
        bad.evidence.append("ref:\u034fforged")
        original = (tuple(good.evidence), tuple(bad.evidence), bad.title)
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as renderer:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([good, bad])
            renderer.assert_not_called()
        self.assertEqual(
            (tuple(good.evidence), tuple(bad.evidence), bad.title), original
        )

    def test_existing_structural_markdown_escape_is_retained(self):
        finding = self.fixture()
        finding.title = "Résumé # fake **bold**"
        finding.evidence = ["résumé:one"]
        rendered = render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn(r"Résumé \# fake \*\*bold\*\*", rendered)
        self.assertIn(r"résumé\:one", rendered)
        self.assertNotIn("**bold**", rendered)

    def test_legitimate_combining_after_base_is_preserved_in_all_fields(self):
        f = self.fixture()
        f.title = "Résumé + e\u0301vidence"
        f.target = "offline.e\u0301xample"
        f.evidence = ["ref:e\u0301vidence", "ref:🔒\ufe0f"]
        f.remediation = "Handle e\u0301 case"
        result = render_escaped_evidence_markdown_optin_w31([f])
        self.assertIn("e\u0301vidence", result)
        self.assertIn("🔒\ufe0f", result)
        self.assertEqual(f.evidence, ["ref:e\u0301vidence", "ref:🔒\ufe0f"])

    def test_invalid_input_is_rejected_before_escaping_the_first_finding(self):
        ok = self.fixture()
        bad = self.fixture("2")
        bad.title = "safe:\ufe0f"
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([ok, bad])
            escape.assert_not_called()


if __name__ == "__main__":
    unittest.main()
