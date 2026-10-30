"""Paired PRIVATE synthetic canary histories: original localhost receipts only."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_canary
from lightup.lab_canary_handoff import save_private_canary_handoff
from lightup.lab_canary_history import compare_private_canary_handoffs


class PrivateCanaryHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic = lab_canary._run_canary()
        if cls.synthetic["status"] != "PASS":
            raise AssertionError("first-party synthetic localhost canary failed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = self.root / "before"
        self.after = self.root / "after"
        self.hold = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False, "failure_stage": "tls",
        }

    def save(self, path, result):
        return save_private_canary_handoff(
            str(path), result, lab_canary._render_text(result)
        )

    def invoke(self):
        stdout = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("history reran the scorer")):
            with redirect_stdout(stdout):
                code = lab_canary.main([
                    "--compare-private-report-dirs", str(self.before),
                    str(self.after), "--format", "json"
                ])
        return code, json.loads(stdout.getvalue()), stdout.getvalue()

    def test_two_unchanged_original_pass_reports_are_locally_stable(self):
        self.save(self.before, self.synthetic)
        self.save(self.after, self.synthetic)
        code, receipt, output = self.invoke()
        self.assertEqual((code, receipt["review_status"]), (0, "PASS"))
        self.assertEqual(receipt["metric_changes"], [])
        self.assertEqual(receipt["regressions"], [])
        for key in ("source_authenticated", "consent_authenticated",
                    "authorization_granted", "deployment",
                    "external_target_authorized"):
            self.assertIs(receipt[key], False)
        self.assertNotIn(str(self.root), output)

    def test_original_pass_to_hold_preserves_global_hold(self):
        self.save(self.before, self.synthetic)
        self.save(self.after, self.hold)
        code, receipt, output = self.invoke()
        self.assertEqual((code, receipt["review_status"]), (2, "HOLD"))
        self.assertEqual(receipt["regressions"], [
            {"metric": "synthetic_canary", "change": "PASS_TO_HOLD"}
        ])
        self.assertEqual(receipt["candidate_status"], "HOLD")
        self.assertNotIn(str(self.root), output)

    def test_hold_to_pass_remains_human_review_and_no_release_pass(self):
        self.save(self.before, self.hold)
        self.save(self.after, self.synthetic)
        code, receipt, output = self.invoke()
        self.assertEqual((code, receipt["review_status"]), (2, "HOLD"))
        self.assertTrue(receipt["human_review_only"])
        self.assertEqual(receipt["baseline_status"], "HOLD")
        self.assertEqual(receipt["candidate_status"], "PASS")
        self.assertIs(receipt["authorization_granted"], False)
        self.assertNotIn(str(self.root), output)

    def test_metric_drift_identifies_regression_without_private_source(self):
        self.save(self.before, self.synthetic)
        later = dict(self.synthetic)
        later["service_inventory_valid_findings"] -= 1
        later["web_baseline_invalid_findings"] += 1
        later["tls_baseline_evidence_quality"] = 0.5
        later["web_baseline_valid_findings"] += 2
        self.save(self.after, later)
        code, receipt, output = self.invoke()
        self.assertEqual((code, receipt["review_status"]), (2, "HOLD"))
        self.assertEqual(len(receipt["regressions"]), 3)
        self.assertEqual(len(receipt["metric_changes"]), 4)
        improved = next(change for change in receipt["metric_changes"]
                        if change["metric"] == "web_baseline_valid_findings")
        self.assertFalse(improved["regression"])
        self.assertNotIn(str(self.root), output)

    def test_manifest_tampering_fail_closed_and_no_private_path_in_receipt(self):
        self.save(self.before, self.synthetic)
        self.save(self.after, self.synthetic)
        source = self.after / "canary.json"
        source.write_bytes(source.read_bytes() + b" ")
        code, receipt, output = self.invoke()
        self.assertEqual((code, receipt["review_status"]), (2, "HOLD"))
        self.assertIs(receipt["input_integrity"], False)
        self.assertIs(receipt["source_authenticated"], False)
        self.assertNotIn(str(self.root), output)

    def test_same_report_twice_is_not_an_independent_comparison(self):
        self.save(self.before, self.synthetic)
        candidate = compare_private_canary_handoffs(str(self.before), str(self.before))
        self.assertEqual(candidate["review_status"], "HOLD")
        self.assertFalse(candidate["selection_valid"])
        self.assertTrue(candidate["input_integrity"])
        self.assertEqual(candidate["metric_changes"], [])
        self.assertEqual(candidate["regressions"][0]["change"], "SAME_PRIVATE_REPORT")
        self.assertFalse(candidate["authorization_granted"])

    def test_human_text_handoff_contains_only_allowlisted_observations(self):
        self.save(self.before, self.synthetic)
        self.save(self.after, self.hold)
        stdout = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("unexpected run")):
            with redirect_stdout(stdout):
                code = lab_canary.main([
                    "--compare-private-report-dirs", str(self.before),
                    str(self.after), "--format", "text"
                ])
        text = stdout.getvalue()
        self.assertEqual(code, 2)
        self.assertIn("Synthetic status regressed from PASS to HOLD.", text)
        self.assertIn("No external target", text)
        self.assertNotIn(str(self.root), text)

    def test_second_source_missing_must_not_leave_partial_metric_success(self):
        self.save(self.before, self.synthetic)
        code, receipt, raw = self.invoke()
        self.assertEqual(code, 2)
        self.assertIs(receipt["input_integrity"], False)
        self.assertEqual(receipt["regressions"], [])
        self.assertEqual(receipt["metric_changes"], [])
        self.assertFalse(receipt["authorization_granted"])
        self.assertNotIn(str(self.root), raw)

    def test_static_human_html_from_original_pair_has_no_network_or_script(self):
        from html.parser import HTMLParser
        self.save(self.before, self.synthetic)
        self.save(self.after, self.synthetic)
        output = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("HTML reran scorer")):
            with redirect_stdout(output):
                code = lab_canary.main([
                    "--compare-private-report-dirs", str(self.before),
                    str(self.after), "--format", "html"
                ])
        self.assertEqual(code, 0)
        markup = output.getvalue()
        class Tags(HTMLParser):
            def __init__(self):
                super().__init__()
                self.tags = []
            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
        inspector = Tags()
        inspector.feed(markup)
        self.assertEqual(inspector.tags.count("table"), 1)
        self.assertEqual(inspector.tags.count("thead"), 1)
        self.assertEqual(inspector.tags.count("caption"), 1)
        self.assertFalse({"script", "iframe", "form"} & set(inspector.tags))
        self.assertIn("NOT AUTHORIZATION", markup)
        self.assertIn("default-src 'none'", markup)
        self.assertNotIn(str(self.root), markup)

    def test_corrupt_source_renders_only_fixed_safe_html_hold(self):
        self.save(self.before, self.synthetic)
        output = io.StringIO()
        with redirect_stdout(output):
            code = lab_canary.main([
                "--compare-private-report-dirs", str(self.before),
                str(self.after), "--format", "html"
            ])
        self.assertEqual(code, 2)
        self.assertIn("HOLD: original private reports", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    def test_normal_canary_refuses_html_before_running_any_scoring(self):
        output = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("should never score")):
            with redirect_stdout(output), self.assertRaises(SystemExit) as err:
                lab_canary.main(["--format", "html"])
        self.assertEqual(err.exception.code, 2)

    def test_original_documents_untouched_by_read_only_comparison(self):
        self.save(self.before, self.synthetic)
        self.save(self.after, self.synthetic)
        original = {
            str(file): (file.read_bytes(), file.stat().st_mode)
            for directory in (self.before, self.after)
            for file in directory.iterdir()
        }
        self.invoke()
        self.assertEqual(original, {
            str(file): (file.read_bytes(), file.stat().st_mode)
            for directory in (self.before, self.after)
            for file in directory.iterdir()
        })


if __name__ == "__main__":
    unittest.main()
