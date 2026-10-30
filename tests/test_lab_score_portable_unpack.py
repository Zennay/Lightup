"""Offline recipient workflow for canonical portable synthetic HUMAN reviews."""
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from lightup import lab_score_calibration as cal
from lightup import lab_score_portable_unpack as unpack


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = cal.main(list(map(str, args)))
    return status, out.getvalue(), err.getvalue()


class UnpackPortableReviewTests(unittest.TestCase):
    def original_pair(self, base):
        sources = [base / "source1", base / "source2"]
        for source in sources:
            self.assertTrue(cal.run_lab_score_calibration(source)["passed"])
        saved = base / "original-private"
        self.assertEqual(cli("--compare-history", *sources, "--format", "html",
                             "--html-output-dir", saved)[0], 0)
        return sources, saved

    def zip_from_originals(self, base, sources, saved, name):
        result = base / name
        code, _, err = cli("--compare-history", *sources, "--format", "html",
                           "--verify-html-output-dir", saved,
                           "--portable-review-output-dir", result)
        self.assertIn(code, (0, 2))
        self.assertEqual(err, "")
        return result / "LightUp-SYNTHETIC-OFFLINE-REVIEW.zip"

    def test_real_synthetic_review_opens_offline_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources, saved = self.original_pair(root)
            source_zip = self.zip_from_originals(root, sources, saved, "portable")
            dest = root / "browse"
            before = source_zip.read_bytes()
            status, output, err = cli("--unpack-portable-review", source_zip,
                                      "--unpack-output-dir", dest)
            self.assertEqual((status, err), (0, ""))
            self.assertIn("OFFLINE FILES READY", output)
            self.assertIn("source NOT authenticated", output)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
            from zipfile import ZipFile
            with ZipFile(source_zip) as z:
                self.assertEqual(set(p.name for p in dest.iterdir()), set(z.namelist()))
                for name in z.namelist():
                    p = dest / name
                    self.assertEqual(p.read_bytes(), z.read(name))
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertIn(b"history.html", (dest/"index.html").read_bytes())
            self.assertEqual(before, source_zip.read_bytes())
            retry, stdout, stderr = cli("--unpack-portable-review", source_zip,
                                        "--unpack-output-dir", dest)
            self.assertEqual((retry, stdout), (2, ""))
            self.assertIn("HOLD", stderr)
            self.assertEqual(before, source_zip.read_bytes())

    def test_tampered_source_never_creates_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources, saved = self.original_pair(root)
            source_zip = self.zip_from_originals(root, sources, saved, "portable")
            private = root / "tampered"
            private.mkdir(mode=0o700)
            tampered = private / source_zip.name
            tampered.write_bytes(source_zip.read_bytes()+b"UNACCOUNTED SYNTHETIC PADDING")
            tampered.chmod(0o600)
            dest = root / "untrusted"
            status, out, err = cli("--unpack-portable-review", tampered,
                                   "--unpack-output-dir", dest)
            self.assertEqual((status, out), (2, ""))
            self.assertFalse(dest.exists())
            self.assertNotIn(str(root), err)
            self.assertIn("HOLD", err)

    def test_nonadjacent_evidence_replay_opens_human_hold_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources, _ = self.original_pair(root)
            newer = root / "source3"
            self.assertTrue(cal.run_lab_score_calibration(newer)["passed"])
            replay = root / "replayed1"
            shutil.copytree(sources[0], replay)
            four = [*sources, newer, replay]
            saved = root / "hold-private"
            self.assertEqual(cli("--compare-history", *four, "--format", "html",
                                 "--html-output-dir", saved)[0], 2)
            archive = self.zip_from_originals(root, four, saved, "hold-zip")
            output = root / "hold-browse"
            status, data, err = cli("--unpack-portable-review", archive,
                                    "--unpack-output-dir", output)
            self.assertEqual((status, err), (2, ""))
            self.assertIn("status HOLD", data)
            self.assertIn("HOLD", (output/"history.html").read_text())
            self.assertEqual(len(list(output.iterdir())), 7)

    def test_publication_failure_rolls_back_owned_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources, saved = self.original_pair(root)
            source_zip = self.zip_from_originals(root, sources, saved, "portable")
            dest = root / "fail-browse"
            original = unpack.os.link
            count = [0]
            def fail_third(*args, **kwargs):
                count[0] += 1
                if count[0] == 3:
                    raise OSError("synthetic mid-publish failure")
                return original(*args, **kwargs)
            with patch.object(unpack.os, "link", side_effect=fail_third):
                status, out, err = cli("--unpack-portable-review", source_zip,
                                       "--unpack-output-dir", dest)
            self.assertEqual((status, out), (2, ""))
            self.assertIn("HOLD", err)
            self.assertEqual(list(dest.iterdir()), [])
            self.assertEqual(count[0], 3)
