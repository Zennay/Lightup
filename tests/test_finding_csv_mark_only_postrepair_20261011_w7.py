"""Independent synthetic postrepair checks for opt-in CSV perceptibility.

No live clients/targets, security assessments, networking or production export.
"""
from __future__ import annotations

import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.finding_export_unicode_integrity import render_findings_csv_checked
from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.models import Finding, Severity, RetestStatus


def item(**updates):
    data = dict(
        finding_id="synthetic-001",
        title="A visible finding",
        severity=Severity.MEDIUM,
        target="demo.invalid",
        remediation="Document and retest",
        retest_status=RetestStatus.NOT_TESTED,
    )
    data.update(updates)
    return Finding(**data)


class CsvPerceptibilityPostrepairTests(unittest.TestCase):
    def test_nfkc_compatibility_modifiers_cannot_masquerade_as_visible_text(self):
        # Originally letter/symbol-like source codepoints NFKC to space+mark,
        # or to a combining mark with no independently readable base.
        for value in ("\uff9e", "\uff9f", "\u00b4", "\u00a8", "\u02dc"):
            with self.subTest(codepoint=ascii(value)):
                for key in ("finding_id", "title", "remediation", "target"):
                    with self.subTest(field=key):
                        with self.assertRaisesRegex(ValueError, "visible base"):
                            render_findings_csv_checked([item(**{key: value})])

    def test_perceptible_bases_with_accent_or_variation_selector_preserved(self):
        for value in ("A\u0301", "\u30ab\u3099", "🍕\ufe0f", "7\u20dd", "✓", "—"):
            with self.subTest(value=ascii(value)):
                csv_text = render_findings_csv_checked([item(title=value)])
                rows = list(csv.DictReader(io.StringIO(csv_text)))
                self.assertEqual(rows[0]["title"], value)
                self.assertEqual(rows[0]["retest_status"], "not_tested")

    def test_formula_escaping_and_unicode_batch_identity_remain_intact(self):
        csv_text = render_findings_csv_checked([
            item(finding_id="Ａ", title="=1+1", remediation="@patch"),
            item(finding_id="b", title="Visible"),
        ])
        records = list(csv.DictReader(io.StringIO(csv_text)))
        self.assertEqual(records[0]["title"], "'=1+1")
        self.assertEqual(records[0]["remediation"], "'@patch")
        self.assertEqual(len(records), 2)
        # NFKC-equivalent finding IDs must still refuse the entire result.
        with self.assertRaisesRegex(ValueError, "ambiguous CSV display identity"):
            render_findings_csv_checked([
                item(finding_id="Ａ"), item(finding_id="A"),
            ])

    def test_malformed_last_item_rejects_whole_batch_without_serializing(self):
        items = [item(finding_id=f"safe-{x}") for x in range(30)]
        items.append(item(finding_id="last", remediation="\uff9e"))
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaisesRegex(ValueError, "visible base"):
                render_findings_csv_checked(items)
            serializer.assert_not_called()

    def test_disposable_tenant_selector_rejects_persisted_compatibility_modifier(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = DomainStore(Path(tmp.name) / "lab.sqlite")
        operator = AccessContext("lab-operator", Role.OPERATOR)
        tenant = store.create_client(operator, "Lab owner")
        other = store.create_client(operator, "Other lab owner")
        eng = store.create_engagement(operator, tenant.client_id, "Authorized offline test")
        foreign = store.create_engagement(operator, other.client_id, "Unrelated lab")
        accepted = store.record_finding(
            operator, eng.engagement_id, "Visible lab finding", Severity.LOW,
            "demo.invalid", "Synthetic impact", "Patch and retest",
            ("synthetic-evidence",),
        )
        store.record_finding(
            operator, eng.engagement_id, "\u00b4", Severity.LOW,
            "demo.invalid", "Synthetic impact", "Patch and retest",
            ("synthetic-evidence",),
        )
        store.record_finding(
            operator, foreign.engagement_id, "Other tenant private title", Severity.LOW,
            "other.invalid", "Synthetic impact", "Patch",
            ("synthetic-evidence",),
        )
        ctx = AccessContext("lab-member", Role.CLIENT_MEMBER, tenant.client_id)
        with store._connect() as conn:
            before = tuple(tuple(row) for row in conn.execute(
                "SELECT finding_id, title, remediation FROM findings ORDER BY finding_id"
            ))
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaisesRegex(ValueError, "visible base"):
                render_tenant_findings_csv_checked(store, ctx, tenant.client_id)
            serializer.assert_not_called()
        with store._connect() as conn:
            after = tuple(tuple(row) for row in conn.execute(
                "SELECT finding_id, title, remediation FROM findings ORDER BY finding_id"
            ))
        self.assertEqual(before, after)
        # Existing source may still be selected only after the corrupted row
        # is excluded by an independently reviewed policy, not by this helper.
        self.assertTrue(accepted.finding_id)


if __name__ == "__main__":
    unittest.main()
