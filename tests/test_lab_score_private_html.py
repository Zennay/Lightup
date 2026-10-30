"""Private, no-overwrite HTML report delivery in synthetic assessment mode."""
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from lightup import lab_score_calibration as cal


class PrivateHtmlDeliveryTests(unittest.TestCase):
    def archives(self, base):
        roots = [Path(base)/str(i) for i in range(2)]
        for root in roots:
            self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
        return roots

    def invoke(self, roots, destination):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = cal.main(["--compare-history", *map(str, roots),
                               "--format", "html",
                               "--html-output-dir", str(destination)])
        return status, out.getvalue(), err.getvalue()

    def verify(self, roots, destination):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = cal.main(["--compare-history", *map(str, roots),
                               "--format", "html",
                               "--verify-html-output-dir", str(destination)])
        return status, out.getvalue(), err.getvalue()

    def test_saved_html_is_reproducibly_verified_without_writes(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            dest = Path(base)/"saved-review"
            self.assertEqual(self.invoke(roots, dest)[0], 0)
            before = (dest/"history.html").stat()
            code, out, err = self.verify(roots, dest)
            after = (dest/"history.html").stat()
            self.assertEqual((code, err), (0, ""))
            self.assertIn("VERIFIED; original comparison PASS", out)
            self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns,
                              before.st_ctime_ns),
                             (after.st_ino, after.st_size, after.st_mtime_ns,
                              after.st_ctime_ns))
            self.assertNotIn(base, out)

    def test_review_output_cannot_mutate_original_archives(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            original = roots[0]
            for destination in (original,
                                original/"candidate"/"private-review",
                                original/"baseline"/"private-review"):
                code, out, err = self.invoke(roots, destination)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("not saved", err)
                self.assertNotIn(base, err)
                self.assertTrue(cal.verify_saved_calibration(original)["passed"])
                self.assertFalse((original/"candidate"/"private-review").exists())
                self.assertFalse((original/"baseline"/"private-review").exists())

    def test_review_output_rejects_ancestor_of_original_archives(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            code, out, err = self.invoke(roots, Path(base))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not saved", err)
            self.assertNotIn(base, err)
            self.assertTrue(all(cal.verify_saved_calibration(root)["passed"]
                                for root in roots))

    def test_review_verify_rejects_source_overlap_without_mutation(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            destination = roots[1]/"candidate"/"review"
            code, out, err = self.verify(roots, destination)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not verified", err)
            self.assertFalse(destination.exists())
            self.assertTrue(all(cal.verify_saved_calibration(root)["passed"]
                                for root in roots))

    def test_original_changed_during_review_publication_is_rolled_back(self):
        from lightup import lab_score_review_store as storage
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            saved = Path(base)/"private-review"
            original_link = storage.os.link
            def mutate_after_private_binding(*args, **kwargs):
                original_link(*args, **kwargs)
                if len(args) > 1 and args[1] == "source_receipt.json":
                    (roots[0]/"candidate"/"report.json").write_bytes(
                        b"modified while publishing"
                    )
            with patch.object(storage.os, "link",
                              side_effect=mutate_after_private_binding):
                code, out, err = self.invoke(roots, saved)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not saved", err)
            self.assertNotIn(base, err)
            self.assertTrue(saved.exists())
            self.assertEqual(set(saved.iterdir()), set())

    def test_swapped_original_archive_during_publish_is_rolled_back(self):
        from lightup import lab_score_review_store as storage
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            alternate = Path(base)/"alternate"
            self.assertTrue(cal.run_lab_score_calibration(alternate)["passed"])
            saved = Path(base)/"private-review"
            original_link = storage.os.link
            def replace_after_binding(*args, **kwargs):
                original_link(*args, **kwargs)
                if len(args) > 1 and args[1] == "source_receipt.json":
                    roots[1].rename(Path(base)/"previous-location")
                    alternate.rename(roots[1])
            with patch.object(storage.os, "link",
                              side_effect=replace_after_binding):
                code, out, err = self.invoke(roots, saved)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not saved", err)
            self.assertNotIn(base, err)
            self.assertFalse((saved/"history.html").exists())
            self.assertFalse((saved/"source_receipt.json").exists())

    def test_source_mutated_during_saved_review_readback_is_hold(self):
        from lightup import lab_score_review_store as storage
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            saved = Path(base)/"bound-review"
            self.assertEqual(self.invoke(roots, saved)[0], 0)
            original = storage._check_saved
            calls = 0
            def mutate_after_read(*args, **kwargs):
                nonlocal calls
                original(*args, **kwargs)
                calls += 1
                if calls == 2:
                    (roots[0]/"candidate"/"report.json").write_bytes(b"changed during readback")
            with patch.object(storage, "_check_saved", side_effect=mutate_after_read):
                code, out, err = self.verify(roots, saved)
            self.assertEqual((code, out), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_source_root_swapped_during_saved_review_readback_is_hold(self):
        from lightup import lab_score_review_store as storage
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            saved = Path(base)/"bound-review"
            self.assertEqual(self.invoke(roots, saved)[0], 0)
            other = Path(base)/"independent"
            self.assertTrue(cal.run_lab_score_calibration(other)["passed"])
            original = storage._check_saved
            calls = 0
            def swap_after_read(*args, **kwargs):
                nonlocal calls
                original(*args, **kwargs)
                calls += 1
                if calls == 2:
                    roots[1].rename(Path(base)/"old-original")
                    other.rename(roots[1])
            with patch.object(storage, "_check_saved", side_effect=swap_after_read):
                code, out, err = self.verify(roots, saved)
            self.assertEqual((code, out), (2, ""))
            self.assertIn("HOLD", err)
            self.assertNotIn(base, err)

    def test_different_original_archives_cannot_reverify_same_score_report(self):
        with tempfile.TemporaryDirectory() as base:
            originals = [Path(base)/str(i) for i in range(4)]
            for root in originals:
                self.assertTrue(cal.run_lab_score_calibration(root)["passed"])
            dest = Path(base)/"source-bound-review"
            self.assertEqual(self.invoke(originals[:2], dest)[0], 0)
            code, out, err = self.verify(originals[2:], dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("HTML review not verified", err)
            self.assertNotIn(base, err)
            self.assertEqual(stat.S_IMODE((dest/"source_receipt.json").stat().st_mode), 0o600)
            self.assertIn("VERIFIED; original comparison PASS",
                          self.verify(originals[:2], dest)[1])

    def test_modified_private_source_binding_fails_reverification(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            dest = Path(base)/"bound-review"
            self.assertEqual(self.invoke(roots, dest)[0], 0)
            (dest/"source_receipt.json").write_bytes(b"invalid private binding")
            code, out, err = self.verify(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertNotIn(base, err)

    def test_tampered_saved_html_fails_reverification(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            dest = Path(base)/"saved-review"
            self.assertEqual(self.invoke(roots, dest)[0], 0)
            (dest/"history.html").write_bytes(b"ALTERED")
            code, out, err = self.verify(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("HTML review not verified", err)
            self.assertNotIn(base, err)

    def test_reused_evidence_hold_is_verifiable_offline(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            shutil.rmtree(roots[1])
            shutil.copytree(roots[0], roots[1])
            dest = Path(base)/"hold-review"
            self.assertEqual(self.invoke(roots, dest)[0], 2)
            code, out, err = self.verify(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(err, "")
            self.assertIn("VERIFIED; original comparison HOLD", out)
            (roots[0]/"report.json").write_bytes(b"corrupted original")
            code, out, err = self.verify(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertNotIn(base, err)

    def test_0600_atomic_new_report_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            dest = Path(base)/"private-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual((code, out, err), (0, "", ""))
            report = dest/"history.html"
            content = report.read_bytes()
            self.assertTrue(content.startswith(b"<!doctype html>"))
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertEqual(set(os.listdir(dest)), {"history.html", "source_receipt.json"})
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("not saved", err)
            self.assertNotIn(base, err)
            self.assertEqual(report.read_bytes(), content)

    def test_post_link_tamper_is_detected_and_report_removed(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            original_link = cal.os.link
            def mutate_published_report(*args, **kwargs):
                original_link(*args, **kwargs)
                if len(args) > 1 and args[1] == "history.html":
                    fd = os.open("history.html", os.O_WRONLY,
                                 dir_fd=kwargs["dst_dir_fd"])
                    try:
                        os.write(fd, b"CORRUPTED")
                    finally:
                        os.close(fd)
            dest = Path(base)/"tampered-review"
            with patch.object(cal.os, "link",
                              side_effect=mutate_published_report):
                code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("HTML review not saved", err)
            self.assertNotIn(base, err)
            self.assertFalse((dest/"history.html").exists())
            self.assertFalse((dest/".history.html.tmp").exists())

    def test_corrupt_source_refuses_to_create_report(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            (roots[1]/"report.json").write_bytes(b"invalid original")
            dest = Path(base)/"new-private-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("archive 2 not verified", err)
            self.assertFalse(dest.exists())
            self.assertNotIn(base, err)

    def test_symlinked_output_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            actual = Path(base)/"actual"
            actual.mkdir(mode=0o700)
            (Path(base)/"alias").symlink_to(actual, target_is_directory=True)
            code, out, err = self.invoke(roots, Path(base)/"alias"/"review")
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertFalse((actual/"review").exists())
            self.assertNotIn(base, err)

    def test_verified_hold_saves_private_report_and_returns_two(self):
        import shutil
        with tempfile.TemporaryDirectory() as base:
            roots = self.archives(base)
            shutil.rmtree(roots[1])
            shutil.copytree(roots[0], roots[1])
            dest = Path(base)/"hold-review"
            code, out, err = self.invoke(roots, dest)
            self.assertEqual(code, 2)
            self.assertEqual((out, err), ("", ""))
            report = dest/"history.html"
            self.assertIn("Overall: HOLD", report.read_text())
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
