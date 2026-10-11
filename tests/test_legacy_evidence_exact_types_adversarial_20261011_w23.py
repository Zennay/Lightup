"""#894: adversarial legacy in-memory Finding evidence admission canaries.

Expected RED on canonical main until a source owner hardens Finding.validate().
Offline synthetic objects only; no network, scopes, grants, or real customer evidence.
"""
from __future__ import annotations

import unittest

from lightup.models import Finding, RetestStatus, Severity
from lightup.reporting import render_markdown


class UnreadableList(list):
    """A subclass must be rejected without invoking its hostile iterator."""

    def __iter__(self):
        raise AssertionError("subclass iterator must not run")

    def __str__(self):
        raise AssertionError("subclass string coercion must not run")


class DeceptiveText(str):
    def strip(self, *args, **kwargs):
        raise AssertionError("subclass strip must not run")

    def __str__(self):
        raise AssertionError("subclass string coercion must not run")


def make_finding(evidence, name="synthetic"):
    return Finding(
        finding_id=name,
        title="Synthetic finding",
        severity=Severity.INFO,
        target="example.invalid",
        evidence=evidence,
        remediation="Synthetic fix only.",
        retest_status=RetestStatus.NOT_TESTED,
    )


class LegacyEvidenceExactTypeBoundaryTests(unittest.TestCase):
    def test_reject_noncanonical_container_before_touching_subclass(self):
        for evidence in (UnreadableList(), UnreadableList(["real"]), (), ("item",), {"item": "x"}, "text", None):
            with self.subTest(container=type(evidence).__name__):
                row = make_finding(evidence)
                with self.assertRaises(ValueError):
                    row.validate()
                self.assertIs(row.evidence, evidence)

    def test_reject_noncanonical_late_item_without_mutation(self):
        for bad in (DeceptiveText("safe"), "", " \t ", None, True, 0, b"byte-string"):
            with self.subTest(item_type=type(bad).__name__, item_repr=repr(bad)):
                evidence = ["first valid", bad]
                row = make_finding(evidence)
                before = tuple(evidence)
                with self.assertRaises(ValueError):
                    row.validate()
                self.assertIs(row.evidence, evidence)
                self.assertEqual(tuple(evidence), before)

    def test_valid_international_evidence_keeps_identity_order_and_fallback(self):
        evidence = ["évidence/検証", "🛡️ preuve", "  space is data  "]
        row = make_finding(evidence)
        row.validate()
        self.assertIs(row.evidence, evidence)
        self.assertEqual(row.evidence, evidence)
        output = render_markdown([row, make_finding([],"empty")])
        self.assertLess(output.index("- évidence/検証"), output.index("- 🛡️ preuve"))
        self.assertIn("-   space is data  ", output)
        self.assertIn("- No evidence recorded.", output)
        self.assertIs(row.evidence, evidence)


if __name__ == "__main__":
    unittest.main()
