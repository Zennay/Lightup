import csv
import io
import unittest
from copy import deepcopy

from lightup.finding_export import render_findings_csv
from lightup.models import Finding, RetestStatus, Severity


def sample(**changes):
    fields = dict(finding_id="finding-1", title="Header issue",
                  severity=Severity.LOW, target="https://private.invalid",
                  remediation="Set the header", evidence=["raw-evidence-secret"],
                  metadata={"password": "metadata-secret"})
    fields.update(changes)
    return Finding(**fields)


def parse(findings):
    return list(csv.DictReader(io.StringIO(render_findings_csv(findings))))


class FindingCsvExportTests(unittest.TestCase):
    def test_empty_export_has_only_fixed_header(self):
        output = render_findings_csv([])
        self.assertEqual(output, '"finding_id","title","severity","retest_status","remediation"\r\n')

    def test_round_trip_quotes_newlines_unicode_and_delimiters(self):
        title = 'Problem, "quoted"; café\nsecond line'
        row = parse([sample(title=title)])[0]
        self.assertEqual(row["title"], title)
        self.assertEqual(row["severity"], "low")
        self.assertEqual(row["retest_status"], "not_tested")
        self.assertEqual(len(row), 5)

    def test_formula_prefixes_are_literal_in_every_free_text_column(self):
        for field in ("finding_id", "title", "remediation"):
            for payload in ("=1+1", "+1+1", "-1+1", "@SUM(1)",
                            "   =1+1", "\t=1+1", "\r=1+1",
                            "\n=1+1", "\x00=1+1"):
                with self.subTest(field=field, payload=payload):
                    row = parse([sample(**{field: payload})])[0]
                    self.assertEqual(row[field], "'" + payload)

    def test_leading_tab_or_newline_is_neutralized_without_formula(self):
        for payload in ("\thello", "\rhello", "\nhello"):
            self.assertEqual(parse([sample(title=payload)])[0]["title"], "'" + payload)

    def test_sensitive_non_summary_fields_are_never_exported(self):
        output = render_findings_csv([sample()])
        for forbidden in ("private.invalid", "raw-evidence-secret", "metadata-secret",
                          "target", "metadata", "evidence"):
            self.assertNotIn(forbidden, output)

    def test_known_credentials_are_redacted_in_all_free_text_columns(self):
        for field in ("finding_id", "title", "remediation"):
            for value in ("password=canary-secret", "Authorization: Bearer canary.secret"):
                with self.subTest(field=field, value=value):
                    output = render_findings_csv([sample(**{field: value})])
                    self.assertNotIn("canary-secret", output)
                    self.assertNotIn("canary.secret", output)
                    self.assertIn("[REDACTED]", output)

    def test_deterministic_order_and_no_input_mutation(self):
        findings = [sample(finding_id="second", title="=1+1"),
                    sample(finding_id="first", retest_status=RetestStatus.FIXED)]
        before = deepcopy(findings)
        first = render_findings_csv(findings)
        self.assertEqual(first, render_findings_csv(findings))
        self.assertEqual(findings, before)
        self.assertEqual([row["finding_id"] for row in parse(findings)], ["second", "first"])

    def test_duplicate_ids_and_invalid_fields_fail_closed(self):
        with self.assertRaises(ValueError):
            render_findings_csv([sample(), sample()])
        for field in ("finding_id", "title", "target", "remediation"):
            for value in ("", "  ", None, 1):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        render_findings_csv([sample(**{field: value})])
        for field, value in (("severity", "low"), ("retest_status", "fixed")):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    render_findings_csv([sample(**{field: value})])

    def test_outer_and_member_types_are_rejected(self):
        class FindingChild(Finding):
            pass
        class TextChild(str):
            pass
        for value in ((), None, [object()], [FindingChild(**sample().__dict__)],
                      [sample(title=TextChild("title"))]):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ValueError):
                    render_findings_csv(value)


if __name__ == "__main__":
    unittest.main()
