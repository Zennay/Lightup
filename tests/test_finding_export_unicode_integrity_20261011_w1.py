"""Offline regression suite for opt-in Unicode CSV presentation admission."""
from __future__ import annotations

import csv
import io
import unittest
from copy import deepcopy
from unittest.mock import patch

from lightup.finding_export import render_findings_csv
from lightup.finding_export_unicode_integrity import (
    MAX_FINDINGS, render_findings_csv_checked,
)
from lightup.models import Finding, RetestStatus, Severity


def example(**changes):
    data = dict(finding_id="finding-1", title="Security header missing",
                severity=Severity.HIGH, target="lab.invalid",
                remediation="Add and test CSP", retest_status=RetestStatus.NOT_TESTED,
                evidence=["do-not-share-evidence"], metadata={"private": "do-not-share-metadata"})
    data.update(changes)
    return Finding(**data)


def cells(findings):
    return list(csv.DictReader(io.StringIO(render_findings_csv_checked(findings))))


class UnicodeCsvIntegrityTests(unittest.TestCase):
    def test_valid_unicode_is_preserved_without_normalization(self):
        title = "Café / 日本語 / Ελληνικά / e\u0301 / 🔒"
        source = example(title=title)
        before = deepcopy(source)
        rows = cells([source])
        self.assertEqual(rows[0]["title"], title)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["retest_status"], "not_tested")
        self.assertEqual(source, before)

    def test_ascii_formula_escapes_remain_in_existing_renderer(self):
        for prefix in ("=", "+", "-", "@"):
            for leading in ("", "  ", "\u00a0"):
                with self.subTest(prefix=prefix, leading=repr(leading)):
                    text = leading + prefix + "SUM(1)"
                    self.assertEqual(cells([example(title=text)])[0]["title"], "'" + text)

    def test_hidden_formatting_rejected_in_every_source_field(self):
        hidden = ("\u200b", "\u200c", "\u200d", "\u202e", "\u2066", "\ufeff", "\u00ad")
        for name in ("finding_id", "title", "remediation", "target"):
            for char in hidden:
                with self.subTest(name=name, codepoint=hex(ord(char))):
                    with self.assertRaises(ValueError):
                        render_findings_csv_checked([example(**{name: char + "=1+1"})])

    def test_compatibility_formula_prefix_rejected_without_escaper_guess(self):
        for prefix in ("\uff1d", "\uff0b", "\ufe62", "\uff0d", "\uff20"):
            if prefix == "\uff20":
                # FULLWIDTH COMMERCIAL AT -> @ under NFKC.
                pass
            with self.subTest(prefix=hex(ord(prefix))):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked([example(title="   " + prefix + "SUM(1)")])

    def test_disguised_formulas_do_not_cross_late_finding_boundary(self):
        first = example()
        second = example(finding_id="finding-2", remediation="\u200b=HYPERLINK(1)")
        before = deepcopy([first, second])
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
            with self.assertRaises(ValueError):
                render_findings_csv_checked([first, second])
            render.assert_not_called()
        self.assertEqual([first, second], before)

    def test_control_private_unassigned_surrogate_and_unicode_breaks_rejected(self):
        for payload in ("\x00", "\r", "\n", "\t", "\x7f",
                        "\ue000", "\ud800", "\u0378", "\u2028", "\u2029"):
            with self.subTest(payload=repr(payload)):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked([example(remediation="Safe " + payload + " text")])

    def test_no_partial_renderer_call_when_later_record_invalid(self):
        fields = (("severity", "high"), ("retest_status", "fixed"),
                  ("title", None), ("target", 10), ("finding_id", ""))
        for name, bad in fields:
            with self.subTest(name=name):
                with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
                    with self.assertRaises(ValueError):
                        render_findings_csv_checked([
                            example(), example(finding_id="f-2", **{name: bad})
                            if name != "finding_id" else example(finding_id=bad)])
                    render.assert_not_called()

    def test_frozen_copy_severs_mutable_caller_source_before_output(self):
        original = example(title="Normal title")
        def mutate_and_render(snapshots):
            self.assertIsNot(snapshots[0], original)
            self.assertEqual(snapshots[0].title, "Normal title")
            original.title = "=mutated-after-preflight"
            original.evidence.append("another-secret")
            return render_findings_csv(snapshots)
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv",
                   side_effect=mutate_and_render):
            output = render_findings_csv_checked([original])
        self.assertIn("Normal title", output)
        self.assertNotIn("mutated-after-preflight", output)
        self.assertNotIn("another-secret", output)

    def test_metadata_evidence_and_targets_remain_off_csv(self):
        output = render_findings_csv_checked([example()])
        self.assertNotIn("do-not-share-evidence", output)
        self.assertNotIn("do-not-share-metadata", output)
        self.assertNotIn("lab.invalid", output)

    def test_existing_redaction_runs_after_validation(self):
        self.assertEqual(cells([example(remediation="password=supersecret")])[0]["remediation"],
                         "password=[REDACTED]")

    def test_byte_bound_not_character_bound(self):
        with self.assertRaises(ValueError):
            render_findings_csv_checked([example(title="🔒" * 2049)])
        self.assertEqual(cells([example(title="🔒" * 2048)])[0]["title"], "🔒" * 2048)

    def test_total_byte_budget_rejects_before_any_serialization(self):
        batch = [example(finding_id=f"f-{i}", title="a" * 1100,
                         remediation="b" * 1100) for i in range(MAX_FINDINGS)]
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
            with self.assertRaisesRegex(ValueError, "size exceeded"):
                render_findings_csv_checked(batch)
            render.assert_not_called()

    def test_batch_count_and_canonical_list_type(self):
        with self.assertRaises(ValueError):
            render_findings_csv_checked([example(finding_id=f"f-{i}")
                                         for i in range(MAX_FINDINGS + 1)])
        for invalid in (None, (), (example(),), object()):
            with self.subTest(invalid=type(invalid)):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked(invalid)
        self.assertEqual(len(cells([])), 0)

    def test_duplicate_ids_refused_before_render(self):
        with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
            with self.assertRaises(ValueError):
                render_findings_csv_checked([example(), example()])
            render.assert_not_called()

    def test_nfkc_equivalent_ids_are_rejected_before_renderer(self):
        for collision in ("finding-Ａ", "finding-Ⓐ", "finding-\u212b"):
            # Some compatibility pairs deliberately have different native ID
            # spellings while their spreadsheet-visible normalization aliases.
            canonical = "finding-" + __import__("unicodedata").normalize("NFKC", collision.split("-")[1])
            if canonical == collision:
                continue
            with self.subTest(collision=collision):
                first = example(finding_id=canonical)
                second = example(finding_id=collision)
                snapshot = deepcopy([first, second])
                with patch("lightup.finding_export_unicode_integrity.render_findings_csv") as render:
                    with self.assertRaisesRegex(ValueError, "ambiguous"):
                        render_findings_csv_checked([first, second])
                    render.assert_not_called()
                self.assertEqual([first, second], snapshot)

    def test_exact_types_for_findings_enum_and_strings(self):
        class TextChild(str):
            pass
        class FindingChild(Finding):
            pass
        for bad in (FindingChild(**example().__dict__),
                    example(title=TextChild("safe")),
                    example(severity="high"),
                    example(retest_status="fixed"),
                    example(remediation=b"bytes")):
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaises(ValueError):
                    render_findings_csv_checked([bad])

    def test_default_source_still_accepts_invisible_prefix(self):
        raw = render_findings_csv([example(title="\u200b=1+1")])
        self.assertIn("\u200b=1+1", raw)
        with self.assertRaises(ValueError):
            render_findings_csv_checked([example(title="\u200b=1+1")])


if __name__ == "__main__":
    unittest.main()
