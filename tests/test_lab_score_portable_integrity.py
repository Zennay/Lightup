"""Canonical ZIP transport rejects invisible concatenated bytes."""
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from zipfile import ZipFile

from lightup import lab_score_calibration as cal


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cal.main([str(x) for x in args])
    return code, out.getvalue(), err.getvalue()


class PortableByteIntegrityTests(unittest.TestCase):
    def test_canonical_zip_accepts_original_refuses_unaccounted_prefix_and_suffix(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            sources = [base / "run1", base / "run2"]
            for source in sources:
                self.assertTrue(cal.run_lab_score_calibration(source)["passed"])
            saved = base / "saved"
            self.assertEqual(cli("--compare-history", *sources, "--format", "html",
                                 "--html-output-dir", saved)[0], 0)
            package_dir = base / "export"
            self.assertEqual(cli("--compare-history", *sources, "--format", "html",
                                 "--verify-html-output-dir", saved,
                                 "--portable-review-output-dir", package_dir)[0], 0)
            original = package_dir / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"
            self.assertEqual(cli("--verify-portable-review", original)[0], 0)
            raw = original.read_bytes()
            for label, altered in (
                ("suffix", raw + b"SYNTHETIC-UNACCOUNTED-POSTSCRIPT"),
                ("prefix", b"SYNTHETIC-UNACCOUNTED-PREFIX" + raw),
            ):
                with self.subTest(label=label):
                    private = base / label
                    private.mkdir(mode=0o700)
                    candidate = private / original.name
                    candidate.write_bytes(altered)
                    candidate.chmod(0o600)
                    # Standard ZIP readers often silently ignore wrapper bytes.
                    with ZipFile(candidate) as archive:
                        self.assertIsNone(archive.testzip())
                    code, output, error = cli("--verify-portable-review", candidate)
                    self.assertEqual((code, output), (2, ""))
                    self.assertIn("HOLD", error)
                    self.assertNotIn(str(base), error)
            self.assertEqual(cli("--verify-portable-review", original)[0], 0)
