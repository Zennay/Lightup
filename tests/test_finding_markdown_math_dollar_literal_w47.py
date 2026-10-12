"""W47: opt-in Markdown math-dollar presentation-integrity acceptance."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import lightup.finding_markdown_escaped_optin_w31 as renderer
from lightup.models import Finding, RetestStatus, Severity


class MarkdownDollarLiteralIntegrityW47(unittest.TestCase):
    def finding(self):
        return Finding(
            finding_id="synthetic:quote$one",
            title="Synthetic $5 budget and $x+y$ token",
            severity=Severity.INFO,
            target="offline.$scope",
            evidence=["ref:$5", "ref:USD €10"],
            remediation="Manual $fix$ review only",
            retest_status=RetestStatus.NOT_TESTED,
            metadata={"hidden": "$not-displayed$"},
        )

    def test_literal_dollar_is_escaped_in_every_displayed_field(self):
        report = renderer.render_escaped_evidence_markdown_optin_w31([self.finding()])
        for snippet in (
            r"quote\$one",
            r"Synthetic \$5 budget and \$x\+y\$ token",
            r"offline\.\$scope",
            r"ref\:\$5",
            r"Manual \$fix\$ review only",
        ):
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, report)
        self.assertNotIn("not-displayed", report)

    def test_multiple_dollars_and_existing_markdown_are_preserved_as_literals(self):
        escaped = renderer._escape_literal("$x$ $$x^2$$ and €10")
        self.assertEqual(escaped, r"\$x\$ \$\$x^2\$\$ and €10")
        self.assertNotIn("&dollar;", escaped)

    def test_nfkc_fullwidth_and_small_dollar_forms_rejected(self):
        for disguised in ("\uff04", "\ufe69"):
            with self.subTest(disguised=repr(disguised)):
                with self.assertRaisesRegex(ValueError, "evidence integrity"):
                    renderer._checked_literal("ref:" + disguised + "amount")

    def test_disguised_math_dollar_in_any_field_fails_before_escaping(self):
        for attribute in ("finding_id", "title", "target", "remediation"):
            with self.subTest(field=attribute):
                finding = self.finding()
                setattr(finding, attribute, "synthetic:\uff04formula")
                with patch.object(renderer, "_escape_literal") as escape:
                    with self.assertRaisesRegex(ValueError, "evidence integrity"):
                        renderer.render_escaped_evidence_markdown_optin_w31([finding])
                    escape.assert_not_called()

    def test_late_disguised_evidence_is_atomic_and_does_not_mutate(self):
        first, later = self.finding(), self.finding()
        later.finding_id = "synthetic:different"
        later.evidence.append("ref:\ufe69late")
        before = (tuple(first.evidence), tuple(later.evidence), dict(later.metadata))
        with patch.object(renderer, "_escape_literal") as escape:
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([first, later])
            escape.assert_not_called()
        self.assertEqual((tuple(first.evidence), tuple(later.evidence), later.metadata), before)

    def test_normal_currency_and_unicode_still_admitted(self):
        finding = self.finding()
        finding.evidence = ["ref:€10", "ref:£50", "ref:¥500", "ref:$2"]
        output = renderer.render_escaped_evidence_markdown_optin_w31([finding])
        self.assertIn(r"ref\:€10", output)
        self.assertIn(r"ref\:£50", output)
        self.assertIn(r"ref\:¥500", output)
        self.assertIn(r"ref\:\$2", output)

    def test_additional_escape_bytes_count_against_rendered_limit(self):
        finding = self.finding()
        output = renderer.render_escaped_evidence_markdown_optin_w31([finding])
        limit = len(output.encode("utf-8"))
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", limit):
            self.assertEqual(renderer.render_escaped_evidence_markdown_optin_w31([finding]), output)
        with patch.object(renderer, "_MAX_OUTPUT_BYTES", limit - 1):
            with self.assertRaisesRegex(ValueError, "evidence integrity"):
                renderer.render_escaped_evidence_markdown_optin_w31([finding])
        self.assertEqual(finding.evidence, ["ref:$5", "ref:USD €10"])


if __name__ == "__main__":
    unittest.main()
