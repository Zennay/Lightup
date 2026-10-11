"""Independent postrepair acceptance for Unicode-mark-obscured CSV formula text.

No target operations, installed ingress, customer tenant or production DB.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.finding_export import render_findings_csv
from lightup.finding_export_service import render_client_findings_csv
from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.finding_export_unicode_integrity import render_findings_csv_checked
from lightup.models import Finding, RetestStatus, Severity


def fixture(**fields):
    base = dict(
        finding_id="f-1", title="Local finding", severity=Severity.LOW,
        target="lab.invalid", remediation="Verify local patch",
        retest_status=RetestStatus.NOT_TESTED,
        evidence=["private-evidence-do-not-share"], metadata={"note": "private-metadata"},
    )
    base.update(fields)
    return Finding(**base)


def csv_rows(raw):
    return list(csv.DictReader(io.StringIO(raw)))


class MarkFormulaPostrepairTests(unittest.TestCase):
    def test_formula_after_mark_and_unicode_spaces_rejected_across_four_fields(self):
        cases = (
            "\u0301=1+1", "\ufe0f@SUM(1)", "\u034f+1+1",
            "\u20dd-1+1", "\u0301 \ufe0f=SUM(1)", " \ufe0f\u2009+SUM(1)",
            "\u0301\uff1dSUM(1)", "\ufe0f\uff20SUM(1)",
        )
        for field in ("finding_id", "title", "target", "remediation"):
            for text in cases:
                with self.subTest(field=field, payload=ascii(text)):
                    with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as writer:
                        with self.assertRaises(ValueError):
                            render_findings_csv_checked([fixture(**{field: text})])
                        writer.assert_not_called()

    def test_late_invalid_row_atomic_and_original_finding_not_modified(self):
        first = fixture(finding_id="first", remediation="No external fix claim")
        second = fixture(finding_id="second", title=" \u0301  =1+1")
        initial = (first.title, first.evidence[:], second.title, second.remediation)
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as writer:
            with self.assertRaises(ValueError):
                render_findings_csv_checked([first, second])
            writer.assert_not_called()
        self.assertEqual(initial, (first.title, first.evidence, second.title, second.remediation))

    def test_visible_base_followed_by_accent_or_variation_selector_remains_allowed(self):
        for title in ("a\u0301=not-a-prefix", "☕\ufe0f approved display",
                      "X\u20dd symbol", "Café · Analyse", "日\u0301本語"):
            with self.subTest(title=ascii(title)):
                rows = csv_rows(render_findings_csv_checked([fixture(title=title)]))
                self.assertEqual(rows[0]["title"], title)

    def test_literal_ascii_prefix_remains_escaped_not_silently_erased(self):
        for title in ("=SUM(1)", " +1+1", "\u00a0@SUM(1)", "-42"):
            with self.subTest(title=title):
                rows = csv_rows(render_findings_csv_checked([fixture(title=title)]))
                self.assertEqual(rows[0]["title"], "'" + title)

    def test_legacy_renderer_still_ungated_and_optin_rejects(self):
        invalid = fixture(title="\u0301=SUM(1)")
        old_rows = csv_rows(render_findings_csv([invalid]))
        self.assertEqual(old_rows[0]["title"], invalid.title)
        with self.assertRaises(ValueError):
            render_findings_csv_checked([invalid])

    def test_disposable_real_tenant_producer_denies_bad_second_finding(self):
        with tempfile.TemporaryDirectory() as temp:
            store = DomainStore(Path(temp) / "lab.sqlite")
            operator = AccessContext("synthetic-operator", Role.OPERATOR)
            client = store.create_client(operator, "Allowed synthetic tenant")
            forbidden = store.create_client(operator, "Foreign synthetic tenant")
            own_ctx = AccessContext("synthetic-member", Role.CLIENT_MEMBER, client.client_id)
            engagement = store.create_engagement(operator, client.client_id, "First authorized lab")
            other = store.create_engagement(operator, forbidden.client_id, "Other lab")
            store.record_finding(
                operator, engagement.engagement_id, "Known allowed title",
                Severity.LOW, "private-target.invalid", "local test impact",
                "Check configuration", ("private-evidence-ref",),
            )
            affected = store.record_finding(
                operator, engagement.engagement_id, "Initially safe",
                Severity.LOW, "private-target.invalid", "local test impact",
                "Temporary patch", ("private-evidence-ref",),
            )
            store.record_finding(
                operator, other.engagement_id, "Do not export foreign tenant",
                Severity.HIGH, "other.invalid", "foreign", "foreign",
                ("foreign-evidence",),
            )
            with store._connect() as con:
                con.execute(
                    "UPDATE findings SET remediation=? WHERE finding_id=?",
                    ("\u0301  \ufe0f=SUM(1)", affected.finding_id),
                )
            with store._connect() as con:
                before = tuple(con.execute(
                    "SELECT finding_id, client_id, title, remediation, retest_status, evidence_ids_json "
                    "FROM findings ORDER BY finding_id"
                ).fetchall())
            with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as serializer:
                with self.assertRaises(ValueError):
                    render_tenant_findings_csv_checked(store, own_ctx, client.client_id)
                serializer.assert_not_called()
            with store._connect() as con:
                self.assertEqual(before, tuple(con.execute(
                    "SELECT finding_id, client_id, title, remediation, retest_status, evidence_ids_json "
                    "FROM findings ORDER BY finding_id"
                ).fetchall()))
            # Default producer remains intentionally unchanged, even with trusted selection.
            default = render_client_findings_csv(store, own_ctx, client.client_id)
            self.assertIn("\u0301  \ufe0f=SUM(1)", default)
            self.assertNotIn("Do not export foreign tenant", default)
            with store._connect() as con:
                con.execute(
                    "UPDATE findings SET remediation=? WHERE finding_id=?",
                    ("Patch locally then request manual retest", affected.finding_id),
                )
            export = render_tenant_findings_csv_checked(store, own_ctx, client.client_id)
            rows = csv_rows(export)
            self.assertEqual(len(rows), 2)
            self.assertNotIn("private-target.invalid", export)
            self.assertNotIn("private-evidence-ref", export)
            self.assertNotIn("Do not export foreign tenant", export)
            self.assertEqual(
                {r["remediation"] for r in rows},
                {"Check configuration", "Patch locally then request manual retest"},
            )


if __name__ == "__main__":
    unittest.main()
