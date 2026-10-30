"""Real original-localhost-source portable HUMAN handoff; no live targets."""
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from zipfile import ZipFile

from lightup import lab_score_calibration as calibration


def invoke(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = calibration.main(list(map(str, args)))
    return status, stdout.getvalue(), stderr.getvalue()


class PortableReviewTests(unittest.TestCase):
    def test_real_source_bound_package_manifest_and_independent_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = [base / "source-1", base / "source-2"]
            for root in roots:
                self.assertTrue(calibration.run_lab_score_calibration(root)["passed"])
            saved, destination = base / "private-saved", base / "portable"
            self.assertEqual(invoke("--compare-history", *roots, "--format", "html",
                                    "--html-output-dir", saved)[0], 0)
            prior = {p.name: p.read_bytes() for p in saved.iterdir()}
            code, out, err = invoke(
                "--compare-history", *roots, "--format", "html",
                "--verify-html-output-dir", saved,
                "--portable-review-output-dir", destination)
            self.assertEqual((code, err), (0, ""))
            self.assertIn("VERIFIED", out)
            self.assertEqual(prior, {p.name: p.read_bytes() for p in saved.iterdir()})
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            zip_path = destination / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
            self.assertEqual(zip_path.stat().st_mode & 0o777, 0o600)
            verify_code, verify_out, verify_err = invoke("--verify-portable-review", zip_path)
            self.assertEqual((verify_code, verify_err), (0, ""))
            self.assertIn("TRANSPORT VERIFIED", verify_out)
            self.assertIn("source NOT authenticated", verify_out)
            self.assertNotIn(str(base), verify_out)
            with ZipFile(zip_path) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(set(archive.namelist()), {
                    "index.html", "history.html", "review.md", "review.csv",
                    "review.json", "README.txt", "manifest.json"})
                manifest = json.loads(archive.read("manifest.json"))
                self.assertTrue(manifest["passed"])
                self.assertEqual(manifest["pairs_checked"], 1)
                self.assertFalse(manifest["authorization_granted"])
                for name, digest in manifest["files"].items():
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)
                html = archive.read("history.html").decode()
                self.assertIn("Browse original archives", html)
                self.assertIn("default-src 'none'", archive.read("index.html").decode())
                for info in archive.infolist():
                    self.assertEqual((info.external_attr >> 16) & 0o777, 0o600)
                combined = b"".join(archive.read(n) for n in archive.namelist())
                self.assertNotIn(str(base).encode(), combined)
                self.assertNotIn(b"original_receipt_sha256", combined)
                self.assertNotIn(b"service_inventory.sqlite3", combined)
            code, out, err = invoke(
                "--compare-history", *roots, "--format", "html",
                "--verify-html-output-dir", saved,
                "--portable-review-output-dir", destination)
            self.assertEqual((code, out), (2, ""))
            self.assertNotIn(str(base), err)
            self.assertTrue(err)
            with ZipFile(zip_path, "a") as changed:
                changed.writestr("original_private_receipt.json", "forbidden")
            verify_code, verify_out, verify_err = invoke("--verify-portable-review", zip_path)
            self.assertEqual((verify_code, verify_out), (2, ""))
            self.assertNotIn(str(base), verify_err)

    def test_nonadjacent_original_replay_yields_portable_global_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = [base / str(i) for i in range(4)]
            for original in roots[:3]:
                self.assertTrue(calibration.run_lab_score_calibration(original)["passed"])
            shutil.copytree(roots[0], roots[3])
            saved, destination = base / "saved", base / "review-kit"
            self.assertEqual(invoke("--compare-history", *roots, "--format", "html",
                                    "--html-output-dir", saved)[0], 2)
            code, out, err = invoke(
                "--compare-history", *roots, "--format", "html",
                "--verify-html-output-dir", saved,
                "--portable-review-output-dir", destination)
            self.assertEqual((code, err), (2, ""))
            self.assertIn("HOLD", out)
            with ZipFile(destination / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip") as archive:
                manifest = json.loads(archive.read("manifest.json"))
                self.assertFalse(manifest["passed"])
                self.assertEqual((manifest["archives_checked"], manifest["pairs_checked"]),
                                 (4, 6))
                self.assertIn(b"HOLD", archive.read("history.html"))
                self.assertIn(b"HOLD", archive.read("review.csv"))
                self.assertNotIn(str(base).encode(), b"".join(
                    archive.read(name) for name in archive.namelist()))
            verify_code, verify_out, verify_err = invoke(
                "--verify-portable-review",
                destination / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip")
            self.assertEqual((verify_code, verify_err), (2, ""))
            self.assertIn("TRANSPORT VERIFIED", verify_out)
            self.assertIn("status HOLD", verify_out)

    def test_refuse_corrupt_private_binding_without_publishing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = [base / "first", base / "second"]
            for root in roots:
                self.assertTrue(calibration.run_lab_score_calibration(root)["passed"])
            saved = base / "private-saved"
            self.assertEqual(invoke("--compare-history", *roots, "--format", "html",
                                    "--html-output-dir", saved)[0], 0)
            (saved / "review_summary.json").write_text("tampered", encoding="utf-8")
            destination = base / "blocked"
            code, out, err = invoke(
                "--compare-history", *roots, "--format", "html",
                "--verify-html-output-dir", saved,
                "--portable-review-output-dir", destination)
            self.assertEqual((code, out), (2, ""))
            self.assertFalse(destination.exists())
            self.assertNotIn(str(base), err)

    def test_cannot_publish_inside_original_archive_or_private_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            roots = [base / "first", base / "second"]
            for root in roots:
                self.assertTrue(calibration.run_lab_score_calibration(root)["passed"])
            saved = base / "private-saved"
            self.assertEqual(invoke("--compare-history", *roots, "--format", "html",
                                    "--html-output-dir", saved)[0], 0)
            for destination in (roots[0] / "newkit", saved / "newkit"):
                code, out, err = invoke(
                    "--compare-history", *roots, "--format", "html",
                    "--verify-html-output-dir", saved,
                    "--portable-review-output-dir", destination)
                self.assertEqual((code, out), (2, ""))
                self.assertFalse(destination.exists())
                self.assertNotIn(str(base), err)
