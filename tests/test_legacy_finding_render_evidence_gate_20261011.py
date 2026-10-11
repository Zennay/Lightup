"""Issue #894: legacy Finding evidence must fail closed before markdown output.

Expected-RED acceptance on current main; no target or network interaction.
The shared models.py/reporting.py production files remain owned elsewhere.
"""
import unittest

from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class _ListSubclass(list):
    pass


class _StrSubclass(str):
    pass


def _finding(evidence):
    return Finding(
        finding_id="finding-1",
        title="Missing CSP",
        severity=Severity.MEDIUM,
        target="lab.invalid",
        evidence=evidence,
        remediation="Add a restrictive CSP.",
        retest_status=RetestStatus.NOT_TESTED,
    )


class LegacyFindingRenderEvidenceGateTests(unittest.TestCase):
    def test_exact_canonical_evidence_and_empty_fallback_remain_supported(self):
        for evidence, expected in [
            (["CSP header missing", "X-Frame-Options missing"],
             "- CSP header missing\n- X-Frame-Options missing"),
            ([], "- No evidence recorded."),
        ]:
            with self.subTest(evidence=evidence):
                finding = _finding(evidence)
                original = list(evidence)
                finding.validate()
                rendered = render_markdown([finding])
                self.assertIn(expected, rendered)
                self.assertEqual(evidence, original)

    def test_noncanonical_containers_fail_before_markdown_output(self):
        for evidence in [
            _ListSubclass(["header missing"]),
            ("header missing",),
            {"header missing": "forged"},
            "header missing",
            None,
        ]:
            with self.subTest(type=type(evidence).__name__):
                finding = _finding(evidence)
                self.assertIs(finding.evidence, evidence)
                with self.assertRaises(ValueError):
                    finding.validate()
                with self.assertRaises(ValueError):
                    render_markdown([finding])
                self.assertIs(finding.evidence, evidence)

    def test_noncanonical_items_fail_without_coercion_or_mutation(self):
        for evidence in [
            [_StrSubclass("header missing")],
            [123],
            [None],
            [""],
            [" \t "],
            ["valid", " \t "],
        ]:
            with self.subTest(items=repr(evidence)):
                finding = _finding(evidence)
                before = list(evidence)
                with self.assertRaises(ValueError):
                    finding.validate()
                with self.assertRaises(ValueError):
                    render_markdown([finding])
                self.assertEqual(evidence, before)
                self.assertIs(finding.evidence, evidence)


if __name__ == "__main__":
    unittest.main()
