"""Real synthetic original archive-focused, read-only recipient workflow."""
from __future__ import annotations

import io
import hashlib
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from lightup import lab_score_calibration as cli


def invoke(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = cli.main(list(map(str, args)))
    return status, out.getvalue(), err.getvalue()


class FocusedPortableReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        originals = [cls.root / f"original-{i}" for i in range(1, 5)]
        cls.originals = originals
        for folder in originals[:3]:
            if not cli.run_lab_score_calibration(folder)["passed"]:
                raise AssertionError("invalid first-party synthetic calibration")
        shutil.copytree(originals[0], originals[3])
        saved, portable = cls.root / "saved", cls.root / "portable"
        if invoke("--compare-history", *originals, "--format", "html",
                  "--html-output-dir", saved)[0] != 2:
            raise AssertionError("expected original reuse HOLD")
        if invoke("--compare-history", *originals, "--format", "html",
                  "--verify-html-output-dir", saved,
                  "--portable-review-output-dir", portable)[0] != 2:
            raise AssertionError("portable original HOLD not saved")
        cls.archive = portable / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_focus_aggregate_hold_never_cleared_by_local_pass(self):
        # Archive 2 has three PASS pairs but 1 and 4 reuse evidence.
        code, out, err = invoke("--verify-portable-review", self.archive,
                                "--focus-archive-index", "2")
        self.assertEqual((code, err), (2, ""))
        self.assertIn("Focused anonymous archive 2: 3 original comparisons, 0 focused HOLD", out)
        self.assertIn("GLOBAL STATUS HOLD", out)
        self.assertIn("Synthetic-only: pair 1-2: PASS", out)
        self.assertNotIn(str(self.root), out)

        code, out, err = invoke("--verify-portable-review", self.archive,
                                "--focus-archive-index", "1", "--format", "json")
        self.assertEqual((code, err), (2, ""))
        receipt = json.loads(out)
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertTrue(receipt["history_content_validated"])
        self.assertFalse(receipt["original_source_authenticated"])
        self.assertFalse(receipt["authorization_granted"])
        focus = receipt["focused_archive"]
        self.assertEqual((focus["archive_index"], focus["comparisons"],
                          focus["hold_pairs"]), (1, 3, 1))
        self.assertEqual(focus["pairs"][0]["review_status"], "HOLD")
        self.assertEqual((focus["pairs"][0]["previous_index"],
                          focus["pairs"][0]["current_index"]), (1, 4))
        self.assertEqual(focus["pairs"][0]["hold_reasons"], ["evidence_reused"])
        self.assertFalse(receipt["focused_archive_untrusted_legacy_claim"])
        self.assertNotIn(str(self.root), out)

    def test_focus_rejects_invalid_archive_number_before_claiming_pass(self):
        for index in ("0", "5", "-1"):
            with self.subTest(index=index):
                code, out, err = invoke("--verify-portable-review", self.archive,
                                        "--focus-archive-index", index,
                                        "--format", "json")
                self.assertEqual((code, err), (2, ""))
                receipt = json.loads(out)
                self.assertTrue(receipt["transport_integrity"])
                self.assertFalse(receipt["selection_valid"])
                self.assertEqual(receipt["portable_transport_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
                self.assertEqual(receipt["review_status"], "HOLD")
                self.assertFalse(receipt["authorization_granted"])
                self.assertNotIn(str(self.root), out)

    def test_pair_drilldown_keeps_global_hold_and_private_paths_hidden(self):
        status, text, err = invoke("--verify-portable-review", self.archive, "--focus-pair", 2, 3)
        self.assertEqual((status, err), (2, ""))
        self.assertIn("Original anonymous pair 2-3: PASS; reasons: none", text)
        self.assertIn("GLOBAL STATUS HOLD", text)
        self.assertIn("Verified source-free ZIP SHA-256: " + hashlib.sha256(self.archive.read_bytes()).hexdigest(), text)
        self.assertNotIn(str(self.root), text)
        status, text, err = invoke("--verify-portable-review", self.archive,
                                   "--focus-pair", 1, 4, "--format", "json")
        self.assertEqual((status, err), (2, ""))
        doc = json.loads(text)
        self.assertTrue(doc["history_content_validated"])
        self.assertEqual(doc["portable_transport_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertFalse(doc["original_source_authenticated"])
        self.assertFalse(doc["authorization_granted"])
        self.assertEqual(doc["review_status"], "HOLD")
        self.assertFalse(doc["focused_pair_untrusted_legacy_claim"])
        self.assertTrue(doc["selection_valid"])
        self.assertEqual(doc["focused_pair"]["hold_reasons"], ["evidence_reused"])
        self.assertEqual(doc["focused_pair"]["review_status"], "HOLD")
        self.assertNotIn(str(self.root), text)

    def test_pair_invalid_indices_fail_closed(self):
        for left, right in ((0, 2), (2, 2), (4, 1), (1, 5), (-1, 2)):
            with self.subTest(pair=(left, right)):
                code, out, err = invoke("--verify-portable-review", self.archive,
                                        "--focus-pair", left, right, "--format", "json")
                self.assertEqual((code, err), (2, ""))
                receipt = json.loads(out)
                self.assertTrue(receipt["transport_integrity"])
                self.assertFalse(receipt["selection_valid"])
                self.assertEqual(receipt["portable_transport_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
                self.assertEqual(receipt["review_status"], "HOLD")
                self.assertNotIn("focused_pair", receipt)

    def test_pair_pass_original_producer(self):
        saved, target = self.root / "pair-pass-saved", self.root / "pair-pass-zip"
        self.assertEqual(invoke("--compare-history", *self.originals[:3],
                                "--format", "html", "--html-output-dir", saved)[0], 0)
        self.assertEqual(invoke("--compare-history", *self.originals[:3],
                                "--format", "html", "--verify-html-output-dir", saved,
                                "--portable-review-output-dir", target)[0], 0)
        code, out, err = invoke("--verify-portable-review", target / self.archive.name,
                                "--focus-pair", 1, 3, "--format", "json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["focused_pair"]["review_status"], "PASS")
        self.assertEqual(json.loads(out)["review_status"], "PASS")

    def test_legacy_focus_is_bounded_untrusted_and_no_html_export(self):
        with ZipFile(self.archive) as source:
            files = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(files["manifest.json"])
        manifest["schema"] = "lightup.lab-score-portable-human-review.v2"
        files["manifest.json"] = (
            json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + "\n"
        ).encode()
        legacy_dir = self.root / "legacy"
        legacy_dir.mkdir(mode=0o700)
        legacy_zip = legacy_dir / self.archive.name
        with ZipFile(legacy_zip, "w", compression=ZIP_DEFLATED) as writer:
            for name, data in sorted(files.items()):
                info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                writer.writestr(info, data)
        legacy_zip.chmod(0o600)
        code, out, err = invoke("--verify-portable-review", legacy_zip,
                                "--focus-archive-index", "1")
        self.assertEqual((code, err), (2, ""))
        self.assertIn("UNTRUSTED CLAIM: Focused anonymous archive 1", out)
        self.assertIn("GLOBAL STATUS HOLD", out)
        code, out, err = invoke("--verify-portable-review", legacy_zip,
                                "--focus-archive-index", "1", "--format", "json")
        self.assertEqual((code, err), (2, ""))
        receipt = json.loads(out)
        self.assertTrue(receipt["focused_archive_untrusted_legacy_claim"])
        self.assertFalse(receipt["history_content_validated"])
        self.assertEqual(receipt["focused_archive"]["hold_pairs"], 1)
        code, out, err = invoke("--verify-portable-review", legacy_zip,
                                "--focus-pair", 1, 4, "--format", "json")
        self.assertEqual((code, err), (2, ""))
        receipt = json.loads(out)
        self.assertTrue(receipt["focused_pair_untrusted_legacy_claim"])
        self.assertTrue(receipt["selection_valid"])
        self.assertEqual(receipt["portable_transport_sha256"], hashlib.sha256(legacy_zip.read_bytes()).hexdigest())
        self.assertFalse(receipt["history_content_validated"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), out)
        browse = self.root / "legacy-browser"
        code, out, err = invoke("--unpack-portable-review", legacy_zip,
                                "--unpack-output-dir", browse)
        self.assertEqual((code, out), (2, ""))
        self.assertFalse(browse.exists())
