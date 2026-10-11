"""Issue #894: a late malformed Finding cannot yield a partial Markdown report.

Synthetic in-memory regression; no target interaction or customer evidence.
Expected RED on main until the existing models.py owner adds evidence validation.
"""
import unittest

from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class TextSubclass(str):
    pass


def finding(identifier, evidence):
    return Finding(
        finding_id=identifier,
        title="Synthetic report row",
        severity=Severity.LOW,
        target="example.invalid",
        evidence=evidence,
        remediation="Synthetic remediation only.",
        retest_status=RetestStatus.NOT_TESTED,
    )


class LegacyEvidenceMixedBatchTests(unittest.TestCase):
    def test_two_canonical_findings_render_in_order_without_mutation(self):
        first = finding("first", ["header absent"])
        second = finding("second", [])
        before = [list(first.evidence), list(second.evidence)]

        markdown = render_markdown([first, second])

        self.assertLess(markdown.index("ID: `first`"), markdown.index("ID: `second`"))
        self.assertIn("- header absent", markdown)
        self.assertIn("- No evidence recorded.", markdown)
        self.assertEqual([first.evidence, second.evidence], before)

    def test_late_invalid_evidence_fails_closed_without_mutating_input(self):
        for bad_evidence in (
            ["valid", ""],
            ["valid", "   "],
            ["valid", None],
            ["valid", 7],
            ["valid", TextSubclass("subclass")],
            ("tuple",),
            {"unexpected": "mapping"},
        ):
            with self.subTest(bad_evidence=repr(bad_evidence)):
                first = finding("first", ["safe"])
                second = finding("second", bad_evidence)
                before = (first.evidence, second.evidence)
                with self.assertRaises(ValueError):
                    render_markdown([first, second])
                self.assertIs(first.evidence, before[0])
                self.assertIs(second.evidence, before[1])
                self.assertEqual(first.evidence, ["safe"])
                self.assertEqual(second.evidence, bad_evidence)


if __name__ == "__main__":
    unittest.main()
