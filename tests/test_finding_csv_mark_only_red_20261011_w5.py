"""Synthetic expected-RED acceptance for nonperceptible finding CSV fields.

The optional guard is not connected to the authenticated default exporter.
No real clients, attacks, targets, scans, or network access.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.finding_export_unicode_integrity import render_findings_csv_checked
from lightup.finding_export_tenant_checked import render_tenant_findings_csv_checked
from lightup.models import Finding, Severity, RetestStatus


def finding(**overrides):
    fields = dict(
        finding_id="synthetic-finding-001",
        title="Visible title",
        severity=Severity.LOW,
        target="example.invalid",
        remediation="Patch the lab fixture",
        retest_status=RetestStatus.NOT_TESTED,
    )
    fields.update(overrides)
    return Finding(**fields)


class MarkOnlyCsvExpectedRed(unittest.TestCase):
    def test_mark_only_finding_id_is_not_a_trustworthy_display_identity(self):
        for value in ("\u0301", "\u20dd", "\ufe0f", "\U000e0100"):
            with self.subTest(value=ascii(value)):
                with self.assertRaisesRegex(ValueError, "visible base"):
                    render_findings_csv_checked([finding(finding_id=value)])

    def test_mark_only_title_cannot_look_like_a_valid_finding(self):
        for value in ("\u0301", "\u0903", "\u20dd", "\ufe0f"):
            with self.subTest(value=ascii(value)):
                with self.assertRaisesRegex(ValueError, "visible base"):
                    render_findings_csv_checked([finding(title=value)])

    def test_mark_only_remediation_cannot_claim_to_offer_a_real_fix(self):
        for value in ("\u0301", "\u20dd", "\ufe0f"):
            with self.subTest(value=ascii(value)):
                with self.assertRaisesRegex(ValueError, "visible base"):
                    render_findings_csv_checked([finding(remediation=value)])

    def test_mark_only_hidden_target_must_fail_before_serializer(self):
        for value in ("\u0301", "\u20dd", "\ufe0f"):
            with self.subTest(value=ascii(value)):
                with patch(
                    "lightup.finding_export_unicode_integrity.render_findings_csv"
                ) as serializer:
                    with self.assertRaisesRegex(ValueError, "visible base"):
                        render_findings_csv_checked([finding(target=value)])
                    serializer.assert_not_called()

    def test_late_invalid_finding_denies_full_batch_without_partial_csv(self):
        batch = [finding(), finding(finding_id="second", title="\u0301")]
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaisesRegex(ValueError, "visible base"):
                render_findings_csv_checked(batch)
            serializer.assert_not_called()

    def test_real_disposable_tenant_producer_refuses_mark_only_title(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = DomainStore(Path(tmp.name) / "synthetic.sqlite")
        op = AccessContext("synthetic-operator", Role.OPERATOR)
        client = store.create_client(op, "Synthetic tenant")
        engagement = store.create_engagement(op, client.client_id, "Synthetic engagement")
        scoped = AccessContext("synthetic-member", Role.CLIENT_MEMBER, client.client_id)
        store.record_finding(
            op, engagement.engagement_id, "\u0301", Severity.LOW,
            "synthetic.invalid", "lab impact", "Repair guidance",
            ("synthetic-evidence-ref",),
        )
        with patch(
            "lightup.finding_export_unicode_integrity.render_findings_csv"
        ) as serializer:
            with self.assertRaisesRegex(ValueError, "visible base"):
                render_tenant_findings_csv_checked(store, scoped, client.client_id)
            serializer.assert_not_called()

    def test_legitimate_combining_accents_emoji_and_symbols_are_not_stripped(self):
        rows = render_findings_csv_checked([
            finding(
                finding_id="cafe\u0301", title="Café\u0301",
                target="lab-🔥\ufe0f.invalid", remediation="Patch A\u20dd now",
            ),
            finding(
                finding_id="visible-2", title="ε\u0301 finding",
                target="lab.invalid", remediation="Repair the item ✓",
            ),
        ])
        items = list(csv.DictReader(io.StringIO(rows)))
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["finding_id"], "cafe\u0301")
        self.assertEqual(items[0]["title"], "Café\u0301")
        self.assertEqual(items[0]["remediation"], "Patch A\u20dd now")


if __name__ == "__main__":
    unittest.main()
