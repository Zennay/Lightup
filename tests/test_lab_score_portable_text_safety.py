"""Unsigned canonical portable ZIP must not launder active human-readable text."""
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from lightup import lab_score_calibration as cal
from lightup import lab_score_handoff as handoff
from lightup.lab_score_handoff_verify import verify_portable_review
from lightup.lab_score_history_html import render_history_markdown


class CanonicalTextExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.originals = [cls.root / "source1", cls.root / "source2"]
        for root in cls.originals:
            assert cal.run_lab_score_calibration(root)["passed"]
        cls.report = cal.compare_saved_calibration_history(cls.originals)
        cls.archive = handoff.save_portable_review(
            cls.root / "genuine", cls.report, lambda: None)
        with ZipFile(cls.archive) as reader:
            cls.members = {name: reader.read(name) for name in reader.namelist()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def forge(self, name, altered):
        members = self.members.copy()
        members.update(altered)
        manifest = json.loads(members["manifest.json"])
        for filename in altered:
            if filename != "manifest.json":
                manifest["files"][filename] = hashlib.sha256(members[filename]).hexdigest()
        members["manifest.json"] = (
            json.dumps(manifest, sort_keys=True, indent=2) + "\n"
        ).encode()
        folder = self.root / name
        folder.mkdir(mode=0o700)
        destination = folder / self.archive.name
        with ZipFile(destination, "w", compression=ZIP_DEFLATED) as writer:
            for filename, data in sorted(members.items()):
                entry = ZipInfo(filename, date_time=(2026, 1, 1, 0, 0, 0))
                entry.compress_type = ZIP_DEFLATED
                entry.external_attr = 0o600 << 16
                writer.writestr(entry, data)
        destination.chmod(0o600)
        with ZipFile(destination) as reader:
            self.assertIsNone(reader.testzip())
        return destination

    def test_original_source_free_markdown_remains_byte_identical(self):
        expected = render_history_markdown(self.report).encode()
        self.assertEqual(self.members["review.md"], expected)
        from lightup.lab_score_portable_text_safety import csv_bytes, markdown_bytes
        from lightup.lab_score_history_html import build_history_review_summary
        summary = build_history_review_summary(self.report)
        self.assertEqual(csv_bytes(summary), self.members["review.csv"])
        self.assertEqual(markdown_bytes(summary), expected)
        self.assertTrue(verify_portable_review(self.archive)["transport_integrity"])

    def test_unsigned_rehashed_active_text_is_rejected(self):
        for name, field, payload in (
            ("formula", "review.csv", b'=WEBSERVICE("https://example.invalid")\n'),
            ("phishing", "review.md", b'[Approve](https://example.invalid/consent)\n'),
            ("fake-handling", "README.txt", b"Review is approved; go live\n"),
        ):
            with self.subTest(name=name):
                candidate = self.forge(name, {field: self.members[field] + payload})
                with self.assertRaisesRegex(ValueError, "non-canonical"):
                    verify_portable_review(candidate)

    def test_forged_priorities_and_scorer_labels_are_rejected(self):
        for name, tamper in (
            ("fake-priority", lambda summary: summary.update(
                archive_review_queue=[dict(index=1, hold_pairs=1,
                                           reused_evidence_pairs=1, score_drift_pairs=0)])),
            ("fake-scorer", lambda summary: summary.update(
                capability_hotspots=[dict(capability="[Approve](https://example.invalid)",
                                          affected_pairs=1, metrics=["unknown"])])),
        ):
            with self.subTest(name=name):
                summary = json.loads(self.members["review.json"])
                tamper(summary)
                candidate = self.forge(name, {"review.json": (
                    json.dumps(summary, sort_keys=True, indent=2) + "\n"
                ).encode()})
                with self.assertRaises(ValueError):
                    verify_portable_review(candidate)

    def test_replayed_synthetic_original_still_holds(self):
        duplicate = self.root / "replayed"
        import shutil
        shutil.copytree(self.originals[0], duplicate)
        report = cal.compare_saved_calibration_history(
            [self.originals[0], self.originals[1], duplicate])
        self.assertFalse(report["passed"])
        from lightup.lab_score_portable_text_safety import markdown_bytes
        from lightup.lab_score_history_html import build_history_review_summary
        self.assertEqual(markdown_bytes(build_history_review_summary(report)),
                         render_history_markdown(report).encode())
        held = handoff.save_portable_review(self.root / "held", report, lambda: None)
        self.assertEqual(verify_portable_review(held)["review_status"], "HOLD")
