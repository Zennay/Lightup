"""Synthetic offline acceptance of alternative opt-in escaped Markdown rendering."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from lightup.finding_markdown_escaped_optin_w31 import (
    _escape_literal,
    render_escaped_evidence_markdown_optin_w31,
)
from lightup.finding_evidence_markdown_checked_optin_w28 import (
    render_checked_findings_markdown,
)
from lightup.models import Finding, RetestStatus, Severity


class EscapedEvidenceMarkdownW31Tests(unittest.TestCase):
    def sample(self) -> Finding:
        return Finding(
            finding_id="synthetic:alpha-1",
            title="Café validation",
            severity=Severity.MEDIUM,
            target="offline.synthetic",
            remediation="Check synthetic config",
            evidence=["evidence:first", "evidence:second"],
            retest_status=RetestStatus.NOT_TESTED,
        )

    def test_plain_unicode_and_original_order(self):
        finding = self.sample()
        finding.title = "Café vérification"
        result = render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn("## Café vérification", result)
        self.assertLess(result.index("evidence\\:first"), result.index("evidence\\:second"))
        self.assertEqual(finding.evidence, ["evidence:first", "evidence:second"])

    def test_user_markdown_syntax_is_escaped_as_literal_text(self):
        finding = self.sample()
        finding.title = "Title # fake **bold** [link](https://invalid.example)"
        finding.remediation = "Fix *first* then " + chr(96) + "verify" + chr(96) + " (offline); foo_bar@example.org"
        result = render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn("\\# fake \\*\\*bold\\*\\*", result)
        self.assertIn("\\[link\\]\\(https\\:\\/\\/invalid\\.example\\)", result)
        self.assertIn("\\*first\\*", result)
        self.assertIn("\\" + chr(96) + "verify\\" + chr(96), result)
        self.assertIn("foo\\_bar\\@example\\.org", result)
        self.assertNotIn("[link](https://", result)

    def test_html_and_entity_sequence_are_escaped_not_interpreted(self):
        f = self.sample()
        f.remediation = "<img src='x' onerror='synthetic'> &lt;safe&gt;"
        output = render_escaped_evidence_markdown_optin_w31([f])
        self.assertIn("&lt;img src=&#x27;x&#x27;", output)
        self.assertIn("&amp;lt;safe&amp;gt;", output)
        self.assertNotIn("<img", output)

    def test_quoted_html_entity_remains_an_entity(self):
        self.assertEqual(_escape_literal("It's safe"), "It&#x27;s safe")
        self.assertEqual(_escape_literal("a & b"), "a &amp; b")

    def test_newlines_bidi_controls_and_surrogates_refused_atomically(self):
        for raw in (
            "safe\n# FORGED SECTION",
            "safe\rnew",
            "safe\tindented",
            "safe\u202eoverride",
            "safe\u200djoiner",
            "safe\u2028separator",
            "bad\ud800surrogate",
            "\u0301unanchored",
            "e \u0301detached",
        ):
            for field in ("title", "remediation", "evidence"):
                with self.subTest(raw=repr(raw), field=field):
                    finding = self.sample()
                    if field == "evidence":
                        finding.evidence.append(raw)
                    else:
                        setattr(finding, field, raw)
                    with patch(
                        "lightup.finding_markdown_escaped_optin_w31._escape_literal"
                    ) as escaped:
                        with self.assertRaisesRegex(ValueError, "evidence integrity"):
                            render_escaped_evidence_markdown_optin_w31([finding])
                        escaped.assert_not_called()

    def test_nfkc_markup_equivalents_denied(self):
        for raw in ("fullwidth\uff1clink\uff1e", "fullwidth\uff3bclick\uff3d", "a\uff40b", "a\uff03b"):
            with self.subTest(raw=repr(raw)):
                f = self.sample()
                f.title = raw
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    render_escaped_evidence_markdown_optin_w31([f])

    def test_invalid_late_finding_aborts_before_render(self):
        good = self.sample()
        bad = self.sample()
        bad.evidence[-1] = "ok\n# forged"
        before = tuple(good.evidence), tuple(bad.evidence)
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal") as escaped:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                render_escaped_evidence_markdown_optin_w31([good, bad])
            escaped.assert_not_called()
        self.assertEqual((tuple(good.evidence), tuple(bad.evidence)), before)

    def test_snapshot_excludes_metadata_and_mutable_caller_evidence(self):
        f = self.sample()
        f.metadata["internal-secret"] = "synthetic-hidden"
        genuine = _escape_literal
        calls = [0]
        def observe(text):
            calls[0] += 1
            if calls[0] == 1:
                f.evidence[0] = "mutated-after-snapshot"
            return genuine(text)
        with patch("lightup.finding_markdown_escaped_optin_w31._escape_literal", side_effect=observe):
            output = render_escaped_evidence_markdown_optin_w31([f])
        self.assertIn("evidence\\:first", output)
        self.assertNotIn("mutated-after-snapshot", output)
        self.assertNotIn("internal-secret", output)
        self.assertNotIn("synthetic-hidden", output)

    def test_container_types_evidence_items_and_limits_fail_closed(self):
        class BadList(list):
            pass
        class BadText(str):
            pass
        f = self.sample()
        for batch in (None, (), BadList([f]), [f] * 129):
            with self.subTest(batch=type(batch).__name__):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    render_escaped_evidence_markdown_optin_w31(batch)
        for candidate in (BadList(["a"]), ("a",), [BadText("a")], [None], [""]):
            f = self.sample()
            f.evidence = candidate
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    render_escaped_evidence_markdown_optin_w31([f])
        huge = self.sample()
        huge.title = "x" * 16_385
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31([huge])
        oversized = [self.sample() for _ in range(128)]
        for item in oversized:
            item.evidence = ["x" * 3072] * 3
        with self.assertRaisesRegex(ValueError, "evidence integrity"):
            render_escaped_evidence_markdown_optin_w31(oversized)

    def test_legacy_unescaped_gap_is_intentionally_not_repaired(self):
        f = self.sample()
        f.title = "An **untrusted** heading"
        self.assertIn("An **untrusted** heading", render_checked_findings_markdown([f]))
        self.assertIn("An \\*\\*untrusted\\*\\* heading", render_escaped_evidence_markdown_optin_w31([f]))

    def test_compatible_empty_batch_and_empty_evidence(self):
        self.assertEqual(
            render_escaped_evidence_markdown_optin_w31([]),
            "# LightUp Assessment Findings\n\nNo findings recorded.\n",
        )
        f = self.sample()
        f.evidence = []
        self.assertIn("- No evidence recorded.", render_escaped_evidence_markdown_optin_w31([f]))


if __name__ == "__main__":
    unittest.main()
