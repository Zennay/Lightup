"""Expected-RED synthetic checks: leading Unicode marks must not disguise CSV formulas."""
from __future__ import annotations

import csv
import io
import unittest
from copy import deepcopy
from unittest.mock import patch

from lightup.finding_export_unicode_integrity import render_findings_csv_checked
from lightup.models import Finding, RetestStatus, Severity


def row(**overrides):
    fields = dict(
        finding_id="f-1",
        title="Synthetic finding",
        severity=Severity.LOW,
        target="lab.invalid",
        remediation="Use safe mock configuration",
        retest_status=RetestStatus.NOT_TESTED,
    )
    fields.update(overrides)
    return Finding(**fields)


def parsed(records):
    return list(csv.DictReader(io.StringIO(render_findings_csv_checked(records))))


class LeadingUnicodeMarkCsvRedTests(unittest.TestCase):
    def test_leading_combining_marks_cannot_hide_ascii_formula(self):
        for mark in ("\u0301", "\u034f", "\ufe0f", "\u20dd"):
            for name in ("title", "remediation", "finding_id", "target"):
                for formula in ("=1+1", "+1+1", "-1+1", "@SUM(1)"):
                    with self.subTest(mark=hex(ord(mark)), field=name, formula=formula):
                        with self.assertRaises(ValueError):
                            render_findings_csv_checked([row(**{name: mark + formula})])

    def test_leading_mark_and_spaces_cannot_hide_formula(self):
        samples = (
            " \u0301 =SUM(1)",
            "\u0301 \ufe0f +SUM(1)",
            "\ufe0f\u00a0@SUM(1)",
            "\u034f\u2009-1+1",
            "\u20dd\u0301  =1+1",
        )
        for sample in samples:
            with self.subTest(sample=ascii(sample)):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked([row(remediation=sample)])

    def test_nfkc_formula_sigil_after_leading_mark_cannot_bypass_guard(self):
        samples = (
            "\u0301\uff1dSUM(1)",  # FULLWIDTH EQUALS
            "\ufe0f\uff0bSUM(1)",  # FULLWIDTH PLUS
            "\u034f\uff20SUM(1)",  # FULLWIDTH AT
        )
        for sample in samples:
            with self.subTest(sample=ascii(sample)):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked([row(title=sample)])

    def test_bad_second_record_cannot_produce_partial_csv(self):
        records = [row(), row(finding_id="f-2", remediation="\ufe0f=1+1")]
        before = deepcopy(records)
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as serializer:
            with self.assertRaises(ValueError):
                render_findings_csv_checked(records)
            serializer.assert_not_called()
        self.assertEqual(records, before)

    def test_real_accents_and_visible_formula_escaping_remain_valid(self):
        samples = (
            "Café étagère",
            "a\u0301 safe composed accent",
            "🔒\ufe0f visible emoji",
            "français, 日本語, Ελληνικά",
        )
        for title in samples:
            with self.subTest(title=title):
                self.assertEqual(parsed([row(title=title)])[0]["title"], title)
        for title in ("=1+1", " =SUM(1)", "\u00a0+SUM(1)", "@SUM(1)"):
            with self.subTest(formula=title):
                self.assertEqual(parsed([row(title=title)])[0]["title"], "'" + title)


if __name__ == "__main__":
    unittest.main()
