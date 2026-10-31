"""Fail-closed first-party portable producer on unsafe review HTML."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from lightup import lab_score_calibration as calibration
from lightup import lab_score_handoff as producer


class ProducerHTMLAdmissionTests(unittest.TestCase):
    def test_real_synthetic_report_emits_inert_offline_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archives = [root / "source1", root / "source2"]
            for archive in archives:
                self.assertTrue(calibration.run_lab_score_calibration(archive)["passed"])
            report = calibration.compare_saved_calibration_history(archives)
            out = root / "offline-safe"
            result = producer.save_portable_review(out, report, lambda: None)
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            from lightup.lab_score_handoff_verify import verify_portable_review
            self.assertTrue(verify_portable_review(result)["transport_integrity"])
            with ZipFile(result) as z:
                self.assertIn(b"Offline HUMAN review", z.read("index.html"))
                self.assertIn(b"default-src 'none'", z.read("history.html"))

    def test_bad_renderer_html_is_refused_before_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archives = [root / "source1", root / "source2"]
            for archive in archives:
                self.assertTrue(calibration.run_lab_score_calibration(archive)["passed"])
            report = calibration.compare_saved_calibration_history(archives)
            valid = producer.render_portable_dashboard(
                producer.build_history_review_summary(report))
            scenarios = (
                ("script-in-dashboard", "render_portable_dashboard",
                 valid.replace("</body>", "<script>/* synthetic */</script></body>")),
                ("remote-link-in-dashboard", "render_portable_dashboard",
                 valid.replace("href='review.md'", "href='https://example.invalid/x'")),
                ("script-in-history", "render_portable_history",
                 "<!doctype html><html lang='en'><meta charset='utf-8'>"
                 "<meta http-equiv='Content-Security-Policy' "
                 "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
                 "<body><script>/* synthetic */</script></body></html>"),
            )
            for name, symbol, altered in scenarios:
                with self.subTest(name=name):
                    output = root / name
                    with patch.object(producer, symbol, return_value=altered):
                        with self.assertRaises(ValueError):
                            producer.save_portable_review(output, report, lambda: None)
                    self.assertFalse(output.exists())
