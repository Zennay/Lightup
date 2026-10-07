from __future__ import annotations

import unittest

from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class EvidenceList(list):
    pass


class EvidenceText(str):
    pass


def _finding(evidence) -> Finding:
    return Finding(
        finding_id="finding-1",
        title="Missing CSP",
        severity=Severity.MEDIUM,
        target="lab.local",
        evidence=evidence,
        remediation="Add a strict Content-Security-Policy header.",
        retest_status=RetestStatus.NOT_TESTED,
    )


class FindingEvidenceIntegrityAcceptanceTests(unittest.TestCase):
    def test_canonical_and_empty_evidence_controls_remain_supported(self) -> None:
        canonical = _finding(["Content-Security-Policy header missing"])
        canonical.validate()
        self.assertIn(
            "- Content-Security-Policy header missing",
            render_markdown([canonical]),
        )

        empty = _finding([])
        empty.validate()
        self.assertIn("- No evidence recorded.", render_markdown([empty]))

    def test_evidence_container_must_be_exact_builtin_list(self) -> None:
        cases = (
            EvidenceList(["header missing"]),
            ("header missing",),
        )

        for evidence in cases:
            with self.subTest(container_type=type(evidence).__name__):
                finding = _finding(evidence)
                before = tuple(evidence)

                with self.assertRaises(ValueError):
                    finding.validate()

                self.assertEqual(tuple(evidence), before)

    def test_evidence_items_must_be_exact_non_blank_strings(self) -> None:
        cases = (
            [EvidenceText("header missing")],
            [123],
            [""],
            ["   \t"],
        )

        for evidence in cases:
            with self.subTest(evidence=evidence):
                finding = _finding(evidence)
                before = list(evidence)

                with self.assertRaises(ValueError):
                    finding.validate()

                self.assertEqual(evidence, before)


if __name__ == "__main__":
    unittest.main()
