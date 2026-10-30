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

    def test_full_queue_prioritizes_original_replay_hold_and_retains_global_hold(self):
        code, raw, err = invoke("--verify-portable-review", self.archive,
                                "--review-queue", "--format", "json")
        self.assertEqual((code, err), (2, ""))
        receipt = json.loads(raw)
        queue = receipt["review_queue"]
        self.assertEqual((queue["pairs_checked"], queue["hold_pairs"],
                          queue["pass_pairs"]), (6, 1, 5))
        self.assertEqual([(a["index"], a["hold_pairs"]) for a in queue["archive_priorities"]],
                         [(1, 1), (4, 1)])
        self.assertTrue(queue["human_review_only"])
        self.assertFalse(queue["source_identity_authenticated"])
        self.assertFalse(receipt["review_queue_untrusted_legacy_claim"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertEqual((queue["pairs"][0]["previous_index"],
                          queue["pairs"][0]["current_index"]), (1, 4))
        self.assertEqual(queue["pairs"][0]["hold_reasons"], ["evidence_reused"])
        self.assertTrue(all(p["review_status"] == "PASS" for p in queue["pairs"][1:]))
        self.assertNotIn(str(self.root), raw)
        code, raw, err = invoke("--verify-portable-review", self.archive, "--review-queue")
        self.assertEqual((code, err), (2, ""))
        self.assertIn("Original pair HUMAN review queue: 6 pairs; 1 HOLD", raw)
        self.assertIn("GLOBAL STATUS HOLD", raw)
        self.assertIn("Synthetic-only: 1. pair 1-4: HOLD", raw)
        self.assertIn("Review archive 1: 1 HOLD pairs", raw)
        self.assertNotIn(str(self.root), raw)

    def test_queue_html_inert_and_global_hold_preserved(self):
        from lightup.lab_score_portable_html_safety import admit_inert_html
        code, html, err = invoke("--verify-portable-review", self.archive,
                                 "--review-queue", "--format", "html")
        self.assertEqual((code, err), (2, ""))
        admit_inert_html(html.encode("utf-8"))
        self.assertIn("GLOBAL STATUS HOLD", html)
        self.assertIn("Pair 1-4", html)
        self.assertLess(html.index("Pair 1-4"), html.index("Pair 1-2"))
        self.assertNotIn("<script", html)
        self.assertNotIn(str(self.root), html)

    def test_queue_workroom_publish_reopen_and_rehashed_tamper(self):
        root = self.root / "queue-new-private-workroom"
        code, out, err = invoke("--publish-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)
        self.assertEqual((code, err), (2, ""))
        self.assertIn("status HOLD", out)
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.name for p in root.iterdir()},
                         {"queue.html", "queue.json", "queue_pairs.csv",
                          "queue_archives.csv", "manifest.json"})
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
        code, out, err = invoke("--verify-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)
        self.assertEqual((code, err), (2, ""))
        self.assertIn("FILES VERIFIED", out)
        code, out, err = invoke("--publish-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        original = (root / "queue.html").read_bytes()
        altered = original.replace(b"HUMAN review", b"HUMAN approval")
        self.assertNotEqual(original, altered)
        (root / "queue.html").write_bytes(altered)
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["file_sha256"]["queue.html"] = hashlib.sha256(altered).hexdigest()
        (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2)+"\n")
        code, out, err = invoke("--verify-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)
        self.assertEqual(code, 2)
        self.assertFalse(out)
        self.assertIn("not verified", err)

    def test_private_queue_spreadsheet_exports_preserve_global_hold(self):
        import csv
        from io import StringIO
        root = self.root / "queue-spreadsheet-workroom"
        code, out, err = invoke("--publish-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)
        self.assertEqual((code, err), (2, ""))
        self.assertEqual({f.name for f in root.iterdir()},
                         {"queue.html", "queue.json", "queue_pairs.csv",
                          "queue_archives.csv", "manifest.json"})
        pairs = list(csv.DictReader(StringIO((root / "queue_pairs.csv").read_text())))
        archives = list(csv.DictReader(StringIO((root / "queue_archives.csv").read_text())))
        self.assertEqual(len(pairs), 6)
        self.assertEqual(len(archives), 2)
        self.assertEqual((pairs[0]["previous_archive"], pairs[0]["current_archive"],
                          pairs[0]["pair_status"]), ("1", "4", "HOLD"))
        self.assertEqual([row["pair_status"] for row in pairs[1:]], ["PASS"] * 5)
        self.assertTrue(all(row["global_status"] == "HOLD" for row in pairs + archives))
        self.assertTrue(all(row["authorization_granted"] == "false" for row in pairs + archives))
        self.assertFalse(any(value.startswith(("=", "+", "-", "@"))
                             for row in pairs + archives for value in row.values()))
        self.assertEqual(invoke("--verify-queue-workroom", self.archive,
                                "--queue-workroom-dir", root)[0], 2)
        # A changed local CSV cannot be legitimized by rewriting unsigned hashes.
        csv_path = root / "queue_pairs.csv"
        changed = csv_path.read_bytes().replace(b"HOLD", b"PASS")
        csv_path.write_bytes(changed)
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["file_sha256"]["queue_pairs.csv"] = hashlib.sha256(changed).hexdigest()
        (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2)+"\n")
        code, text, error = invoke("--verify-queue-workroom", self.archive,
                                  "--queue-workroom-dir", root)
        self.assertEqual((code, text), (2, ""))
        self.assertIn("not verified", error)

    def test_v1_saved_three_file_queue_workroom_still_reopens(self):
        from lightup import lab_score_queue_workroom as workroom
        old = self.root / "old-v1-queue-workroom"
        old.mkdir(mode=0o700)
        _, original_files = workroom._payloads(self.archive, version=1)
        self.assertEqual(set(original_files), {"queue.html", "queue.json", "manifest.json"})
        for name, content in original_files.items():
            target = old / name
            target.write_bytes(content)
            target.chmod(0o600)
        code, out, err = invoke("--verify-queue-workroom", self.archive,
                                "--queue-workroom-dir", old)
        self.assertEqual((code, err), (2, ""))
        self.assertIn("FILES VERIFIED", out)

    def test_failed_queue_publication_rolls_back_only_owned_files_and_allows_retry(self):
        from unittest.mock import patch
        from lightup import lab_score_queue_workroom as workroom
        directory = self.root / "queue-failed-then-retry"
        with patch.object(workroom, "verify_queue_workroom",
                          side_effect=ValueError("simulated recipient readback failure")):
            with self.assertRaises(ValueError):
                workroom.publish_queue_workroom(self.archive, directory)
        self.assertFalse(directory.exists())
        code, out, err = invoke("--publish-queue-workroom", self.archive,
                                "--queue-workroom-dir", directory)
        self.assertEqual((code, err), (2, ""))
        self.assertIn("FILES VERIFIED", out)

    def test_queue_publication_failure_preserves_unowned_local_file(self):
        from unittest.mock import patch
        from lightup import lab_score_queue_workroom as workroom
        directory = self.root / "queue-failed-with-human-file"
        def competing_writer(_source, destination):
            extra = Path(destination) / "human-note.txt"
            extra.write_text("human-local-note")
            extra.chmod(0o600)
            raise ValueError("simulated independent writer")
        with patch.object(workroom, "verify_queue_workroom", side_effect=competing_writer):
            with self.assertRaises(ValueError):
                workroom.publish_queue_workroom(self.archive, directory)
        self.assertTrue(directory.is_dir())
        self.assertEqual({file.name for file in directory.iterdir()}, {"human-note.txt"})
        self.assertEqual((directory / "human-note.txt").read_text(), "human-local-note")

    def test_renderers_refuse_contradictory_global_pass_and_pair_claims(self):
        from copy import deepcopy
        from lightup.lab_score_handoff_verify import verify_portable_review
        from lightup.lab_score_portable_queue import render_portable_queue_html
        from lightup.lab_score_queue_csv import render_queue_csv
        original = verify_portable_review(self.archive, review_queue=True)["review_queue"]
        self.assertEqual(original["hold_pairs"], 1)
        from lightup.lab_score_portable_queue import render_portable_queue
        with self.assertRaises(ValueError):
            render_portable_queue(original, global_status="PASS", legacy=False)
        for renderer in (render_portable_queue_html, render_queue_csv):
            with self.subTest(renderer=renderer.__name__, error="false global pass"):
                with self.assertRaises(ValueError):
                    renderer(original, global_status="PASS")
            with self.subTest(renderer=renderer.__name__, error="forged pair pass"):
                forgery = deepcopy(original)
                forgery["pairs"][0]["review_status"] = "PASS"
                with self.assertRaises(ValueError):
                    renderer(forgery, global_status="HOLD")
            with self.subTest(renderer=renderer.__name__, error="altered priority"):
                forgery = deepcopy(original)
                forgery["archive_priorities"][0]["hold_pairs"] += 1
                with self.assertRaises(ValueError):
                    renderer(forgery, global_status="HOLD")
            with self.subTest(renderer=renderer.__name__, error="false authority"):
                forgery = deepcopy(original)
                forgery["source_identity_authenticated"] = True
                with self.assertRaises(ValueError):
                    renderer(forgery, global_status="HOLD")

    def test_renderers_require_complete_canonical_original_pair_matrix(self):
        from copy import deepcopy
        from lightup.lab_score_handoff_verify import verify_portable_review
        from lightup.lab_score_portable_queue import render_portable_queue_html
        from lightup.lab_score_queue_csv import render_queue_csv
        queue = verify_portable_review(self.archive, review_queue=True)["review_queue"]
        for renderer in (render_portable_queue_html, render_queue_csv):
            # Drop the only original replay HOLD and recalculate every
            # untrusted summary. A truncated matrix must still be rejected.
            missing = deepcopy(queue)
            missing["pairs"].pop(0)
            missing["pairs_checked"] -= 1
            missing["hold_pairs"] = 0
            missing["pass_pairs"] = len(missing["pairs"])
            missing["archive_priorities"] = []
            with self.subTest(renderer=renderer.__name__, error="missing original HOLD"):
                with self.assertRaises(ValueError):
                    renderer(missing, global_status="PASS")
            swapped = deepcopy(queue)
            swapped["pairs"][0], swapped["pairs"][1] = swapped["pairs"][1], swapped["pairs"][0]
            with self.subTest(renderer=renderer.__name__, error="HOLD not first"):
                with self.assertRaises(ValueError):
                    renderer(swapped, global_status="HOLD")

    def test_direct_csv_queue_verifies_zip_and_remains_globally_hold(self):
        import csv
        from io import StringIO
        status, output, err = invoke("--verify-portable-review", self.archive,
                                     "--review-queue", "--format", "review-csv")
        self.assertEqual((status, err), (2, ""))
        rows = list(csv.DictReader(StringIO(output)))
        self.assertEqual(len(rows), 6)
        self.assertEqual((rows[0]["previous_archive"], rows[0]["current_archive"],
                          rows[0]["pair_status"]), ("1", "4", "HOLD"))
        self.assertTrue(all(p["global_status"] == "HOLD" and
                            p["authorization_granted"] == "false" for p in rows))
        self.assertNotIn(str(self.root), output)

    def test_saved_queue_workroom_reexports_both_csvs_after_source_reinspection(self):
        import csv
        from io import StringIO
        room = self.root / "saved-export-v2"
        self.assertEqual(invoke("--publish-queue-workroom", self.archive,
                                "--queue-workroom-dir", room)[0], 2)
        for mode, filename, expected_count in (("review-csv", "queue_pairs.csv", 6),
                                               ("csv", "queue_archives.csv", 2)):
            code, raw, error = invoke("--verify-queue-workroom", self.archive,
                                      "--queue-workroom-dir", room,
                                      "--format", mode)
            self.assertEqual((code, error), (2, ""))
            self.assertEqual(raw.encode("utf-8"), (room / filename).read_bytes())
            rows = list(csv.DictReader(StringIO(raw)))
            self.assertEqual(len(rows), expected_count)
            self.assertTrue(all(row["global_status"] == "HOLD" for row in rows))
            self.assertNotIn(str(self.root), raw)
        # v1 has no saved CSV members; the same source is still reverified
        # and the canonical CSV is derived only after complete v1 reinspection.
        old = self.root / "saved-export-v1"
        old.mkdir(mode=0o700)
        from lightup.lab_score_queue_workroom import _payloads
        for name, data in _payloads(self.archive, version=1)[1].items():
            target = old / name
            target.write_bytes(data)
            target.chmod(0o600)
        code, raw, error = invoke("--verify-queue-workroom", self.archive,
                                  "--queue-workroom-dir", old,
                                  "--format", "review-csv")
        self.assertEqual((code, error), (2, ""))
        self.assertEqual(len(list(csv.DictReader(StringIO(raw)))), 6)
        (room / "queue_pairs.csv").write_text("=HYPERLINK(unsafe)\n")
        code, raw, error = invoke("--verify-queue-workroom", self.archive,
                                  "--queue-workroom-dir", room,
                                  "--format", "review-csv")
        self.assertEqual((code, raw), (2, ""))
        self.assertIn("not verified", error)

    def test_saved_workroom_html_json_csv_exports_bound_to_original_zip(self):
        from lightup.lab_score_portable_html_safety import admit_inert_html
        room = self.root / "saved-full-recipient"
        status, out, error = invoke("--publish-queue-workroom", self.archive,
                                    "--queue-workroom-dir", room)
        self.assertEqual((status, error), (2, ""))
        for name, output in (("html", "queue.html"),
                             ("review-json", "queue.json"),
                             ("csv", "queue_archives.csv"),
                             ("review-csv", "queue_pairs.csv")):
            code, rendered, err = invoke("--verify-queue-workroom", self.archive,
                                         "--queue-workroom-dir", room,
                                         "--format", name)
            self.assertEqual((code, err), (2, ""))
            self.assertEqual(rendered.encode(), (room / output).read_bytes())
            if name == "html":
                admit_inert_html(rendered.encode())
            if name == "review-json":
                receipt = json.loads(rendered)
                self.assertEqual(receipt["review_status"], "HOLD")
                self.assertFalse(receipt["authorization_granted"])
        old = self.root / "saved-full-recipient-v1"
        old.mkdir(mode=0o700)
        from lightup.lab_score_queue_workroom import _payloads
        for name, data in _payloads(self.archive, version=1)[1].items():
            file = old / name
            file.write_bytes(data)
            file.chmod(0o600)
        for mode in ("html", "review-json", "csv", "review-csv"):
            code, data, err = invoke("--verify-queue-workroom", self.archive,
                                     "--queue-workroom-dir", old,
                                     "--format", mode)
            self.assertEqual((code, err), (2, ""))
            self.assertTrue(data)
        (room / "queue.html").write_text("<script>unsafe</script>")
        for mode in ("html", "review-json", "csv", "review-csv"):
            code, data, err = invoke("--verify-queue-workroom", self.archive,
                                     "--queue-workroom-dir", room,
                                     "--format", mode)
            self.assertEqual((code, data), (2, ""))
            self.assertIn("not verified", err)

    def test_queue_workroom_rechecks_original_after_reading_files(self):
        from unittest.mock import patch
        from lightup import lab_score_queue_workroom as workroom
        source_dir = self.root / "queue-race-source"
        source_dir.mkdir(mode=0o700)
        original = source_dir / self.archive.name
        original.write_bytes(self.archive.read_bytes())
        original.chmod(0o600)
        room = self.root / "queue-race-output"
        status, output, error = invoke("--publish-queue-workroom", original,
                                       "--queue-workroom-dir", room)
        self.assertEqual((status, error), (2, ""))
        self.assertIn("FILES VERIFIED", output)
        inspect_file = workroom._check_file
        changed = False
        def source_change(fd, name, expected):
            nonlocal changed
            if not changed:
                changed = True
                with original.open("ab") as writer:
                    writer.write(b"appended-private-data")
            return inspect_file(fd, name, expected)
        with patch.object(workroom, "_check_file", side_effect=source_change):
            with self.assertRaises(ValueError):
                workroom.verify_queue_workroom(original, room)
        self.assertTrue(changed)

    def test_queue_workroom_corrupt_zip_creates_no_private_output(self):
        evil_dir = self.root / "private-queue-corrupt-source"
        evil_dir.mkdir(mode=0o700)
        evil = evil_dir / self.archive.name
        evil.write_bytes(self.archive.read_bytes()+b"extra-false-source")
        evil.chmod(0o600)
        output = self.root / "private-queue-bad-output"
        code, out, err = invoke("--publish-queue-workroom", evil,
                                "--queue-workroom-dir", output)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertFalse(output.exists())
        self.assertNotIn(str(self.root), err)

    def test_queue_rejects_tampered_transport_before_pair_projection(self):
        evil = self.root / "queue-tampered"
        evil.mkdir(mode=0o700)
        path = evil / self.archive.name
        path.write_bytes(self.archive.read_bytes() + b"untrusted-extra-trailer")
        path.chmod(0o600)
        code, raw, err = invoke("--verify-portable-review", path,
                                "--review-queue", "--format", "json")
        self.assertEqual((code, err), (2, ""))
        data = json.loads(raw)
        self.assertFalse(data["transport_integrity"])
        self.assertEqual(data["review_status"], "HOLD")
        self.assertNotIn("review_queue", data)
        self.assertFalse(data["original_source_authenticated"])

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
        status, raw, err = invoke("--verify-portable-review", legacy_zip,
                                  "--review-queue", "--format", "json")
        self.assertEqual((status, err), (2, ""))
        legacy_queue = json.loads(raw)
        status, html, err = invoke("--verify-portable-review", legacy_zip,
                                   "--review-queue", "--format", "html")
        self.assertEqual(status, 2)
        self.assertEqual(html, "")
        self.assertIn("HTML NOT admitted", err)
        status, csvout, err = invoke("--verify-portable-review", legacy_zip,
                                     "--review-queue", "--format", "review-csv")
        self.assertEqual((status, csvout), (2, ""))
        self.assertIn("CSV NOT admitted", err)
        self.assertTrue(legacy_queue["review_queue_untrusted_legacy_claim"])
        self.assertFalse(legacy_queue["history_content_validated"])
        self.assertEqual(legacy_queue["review_status"], "HOLD")
        self.assertEqual(legacy_queue["review_queue"]["hold_pairs"], 1)
        self.assertTrue(receipt["focused_pair_untrusted_legacy_claim"])
        self.assertTrue(receipt["selection_valid"])
        self.assertEqual(receipt["portable_transport_sha256"], hashlib.sha256(legacy_zip.read_bytes()).hexdigest())
        self.assertFalse(receipt["history_content_validated"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), out)
        legacy_queue_dir = self.root / "legacy-queue-workroom"
        code, out, err = invoke("--publish-queue-workroom", legacy_zip,
                                "--queue-workroom-dir", legacy_queue_dir)
        self.assertEqual((code, out), (2, ""))
        self.assertFalse(legacy_queue_dir.exists())
        browse = self.root / "legacy-browser"
        code, out, err = invoke("--unpack-portable-review", legacy_zip,
                                "--unpack-output-dir", browse)
        self.assertEqual((code, out), (2, ""))
        self.assertFalse(browse.exists())
