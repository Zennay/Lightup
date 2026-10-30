"""Real synthetic M1 offline portable HUMAN workroom workflow."""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from lightup import lab_canary
from lightup.lab_canary_handoff import save_private_canary_handoff
from lightup.lab_canary_history import compare_private_canary_handoffs
from lightup.lab_canary_history_store import save_private_history_snapshot
from lightup.lab_canary_workroom import (
    export_private_history_workroom, verify_private_history_workroom,
    unpack_private_history_workroom,
)


class SourceFreePrivateHistoryWorkroomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = lab_canary._run_canary()
        if cls.result["status"] != "PASS":
            raise AssertionError("synthetic local first-party canary did not PASS")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.first = self.root / "source-a"
        self.second = self.root / "source-b"
        self.snap1 = self.root / "history-one"
        self.snap2 = self.root / "history-two"
        self.zipfile = self.root / "portable.zip"
        for p in (self.first, self.second):
            save_private_canary_handoff(str(p), self.result,
                                        lab_canary._render_text(self.result))
        save_private_history_snapshot(str(self.snap1),
                                      compare_private_canary_handoffs(
                                          str(self.first), str(self.second)))
        save_private_history_snapshot(str(self.snap2),
                                      compare_private_canary_handoffs(
                                          str(self.second), str(self.first)))

    def export(self, *sources):
        return export_private_history_workroom(
            list(sources) if sources else [str(self.snap1), str(self.snap2)],
            str(self.zipfile),
        )

    def invoke(self, *args):
        out = io.StringIO()
        with patch.object(lab_canary, "_run_canary",
                          side_effect=AssertionError("unexpected scorer execution")):
            with redirect_stdout(out):
                status = lab_canary.main(list(map(str, args)))
        return status, json.loads(out.getvalue()), out.getvalue()

    def test_original_two_pass_source_free_zip_and_independent_reopen(self):
        created = self.export()
        admitted = verify_private_history_workroom(str(self.zipfile))
        self.assertEqual(created, admitted)
        self.assertEqual(admitted["review_status"], "PASS")
        self.assertEqual(admitted["reports_checked"], 2)
        self.assertEqual(admitted["anonymous_statuses"], ["PASS", "PASS"])
        self.assertEqual(self.zipfile.stat().st_mode & 0o777, 0o600)
        self.assertFalse(admitted["authorization_granted"])
        self.assertFalse(admitted["source_authenticated"])
        self.assertNotIn(str(self.root), str(admitted))
        with ZipFile(self.zipfile) as z:
            names = z.namelist()
            self.assertEqual(len(names), 9)
            self.assertEqual(len(set(names)), len(names))
            self.assertTrue(all(name.startswith("reports/")
                                or name in {"index.html", "README.txt",
                                            "transport-manifest.json"}
                                for name in names))
            html = z.read("index.html")
            self.assertIn(b"default-src 'none'", html)
            self.assertNotIn(b"<script", html)
            self.assertIn(b"reports/02/history.html", html)

    def test_cli_producer_recipient_no_scorer_or_untrusted_paths(self):
        code, receipt, out = self.invoke(
            "--export-private-history-workroom", self.zipfile,
            "--private-history-snapshots", self.snap1, self.snap2, "--format", "json",
        )
        self.assertEqual(code, 0)
        self.assertEqual(receipt["review_status"], "PASS")
        self.assertNotIn(str(self.root), out)
        code, verified, out = self.invoke(
            "--verify-private-history-workroom", self.zipfile, "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(receipt, verified)
        self.assertNotIn(str(self.root), out)

    def test_held_original_snapshot_remains_global_hold(self):
        from shutil import rmtree
        rmtree(self.second)
        hold = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False, "failure_stage": "http",
        }
        save_private_canary_handoff(str(self.second), hold,
                                    lab_canary._render_text(hold))
        third = self.root / "hold-original"
        save_private_history_snapshot(str(third),
                                      compare_private_canary_handoffs(
                                          str(self.first), str(self.second)))
        result = self.export(str(self.snap1), str(third))
        self.assertEqual(result["review_status"], "HOLD")
        self.assertEqual(result["anonymous_statuses"], ["PASS", "HOLD"])
        self.assertFalse(result["deployment"])
        with ZipFile(self.zipfile) as z:
            index = z.read("index.html").decode("utf-8")
            self.assertIn("Global synthetic review: <strong>HOLD</strong>", index)
            self.assertLess(index.index("Original anonymous review 2"),
                            index.index("Original anonymous review 1"))
            self.assertIn("A local PASS never clears a global HOLD.", index)
        code, receipt, raw = self.invoke(
            "--verify-private-history-workroom", self.zipfile, "--format", "json"
        )
        self.assertEqual(code, 2)
        self.assertTrue(receipt["transport_integrity"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), raw)

    def test_same_physical_original_cannot_masquerade_as_two_sources(self):
        with self.assertRaises(ValueError):
            self.export(str(self.snap1), str(self.snap1))
        self.assertFalse(self.zipfile.exists())
        with self.assertRaises(ValueError):
            self.export(str(self.snap1))
        self.assertFalse(self.zipfile.exists())

    def test_no_overwrite_or_following_zip_symlink(self):
        self.export()
        with self.assertRaises(FileExistsError):
            self.export()
        alias = self.root / "alias.zip"
        alias.symlink_to(self.zipfile)
        with self.assertRaises(OSError):
            verify_private_history_workroom(str(alias))

    def test_bad_original_snapshot_holds_before_creating_zip(self):
        (self.snap2 / "history.json").write_bytes(
            (self.snap2 / "history.json").read_bytes() + b" "
        )
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.zipfile.exists())

    def test_tampered_zip_with_fake_digest_is_still_refused(self):
        self.export()
        raw = self.zipfile.read_bytes()
        with ZipFile(io.BytesIO(raw)) as original:
            parts = {name: original.read(name) for name in original.namelist()}
        altered = parts["reports/01/history.html"].replace(
            b"NOT AUTHORIZATION", b"AUTHORIZED TO RUN EXTERNAL TESTS"
        )
        parts["reports/01/history.html"] = altered
        inner = json.loads(parts["reports/01/manifest.json"])
        inner["files"]["history.html"] = hashlib.sha256(altered).hexdigest()
        parts["reports/01/manifest.json"] = json.dumps(inner).encode()
        outer = json.loads(parts["transport-manifest.json"])
        for name in ("reports/01/history.html", "reports/01/manifest.json"):
            outer["files"][name] = hashlib.sha256(parts[name]).hexdigest()
        parts["transport-manifest.json"] = json.dumps(outer).encode()
        self.zipfile.unlink()
        with ZipFile(self.zipfile, "w", compression=ZIP_DEFLATED) as z:
            for name, payload in parts.items():
                info = ZipInfo(name)
                info.compress_type = ZIP_DEFLATED
                info.external_attr = 0o100600 << 16
                z.writestr(info, payload)
        self.zipfile.chmod(0o600)
        code, receipt, raw = self.invoke(
            "--verify-private-history-workroom", self.zipfile, "--format", "json"
        )
        self.assertEqual(code, 2)
        self.assertFalse(receipt["transport_integrity"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertNotIn(str(self.root), raw)

    def test_eight_independent_originals_bounded_and_hold_priority(self):
        import shutil
        original = [str(self.snap1)]
        for n in range(2, 9):
            path = self.root / f"independent-{n}"
            shutil.copytree(self.snap2, path)
            original.append(str(path))
        result = self.export(*original)
        self.assertEqual(result["reports_checked"], 8)
        self.assertEqual(result["review_status"], "PASS")
        self.assertEqual(len(result["anonymous_statuses"]), 8)
        with ZipFile(self.zipfile) as z:
            self.assertEqual(len(z.namelist()), 27)
            self.assertIn("reports/08/history.json", z.namelist())
        self.zipfile.unlink()
        original.append(original[-1])
        with self.assertRaises(ValueError):
            self.export(*original)
        self.assertFalse(self.zipfile.exists())

    def test_real_verified_source_free_zip_unpack_and_private_browser_entry(self):
        self.export()
        target = self.root / "recipient-new-private-directory"
        output = unpack_private_history_workroom(str(self.zipfile), str(target))
        self.assertEqual(output["review_status"], "PASS")
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(".INCOMPLETE", [p.name for p in target.iterdir()])
        self.assertTrue((target / "reports" / "01" / "history.html").is_file())
        self.assertTrue((target / "reports" / "02" / "history.json").is_file())
        self.assertEqual((target / "reports").stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600
                            for p in target.rglob("*") if p.is_file()))
        self.assertIn("reports/01/history.html", (target / "index.html").read_text())
        with self.assertRaises(FileExistsError):
            unpack_private_history_workroom(str(self.zipfile), str(target))

    def test_cli_extract_with_opted_synthetic_hold_keeps_global_hold(self):
        from shutil import rmtree
        rmtree(self.second)
        held = {"status": "HOLD", "passed": False, "lab_only": True,
                "external_target_authorized": False,
                "deployment_authorized": False, "failure_stage": "service"}
        save_private_canary_handoff(str(self.second), held,
                                    lab_canary._render_text(held))
        held_snapshot = self.root / "original-held-review"
        save_private_history_snapshot(str(held_snapshot),
            compare_private_canary_handoffs(str(self.first), str(self.second)))
        self.export(str(self.snap1), str(held_snapshot))
        target = self.root / "opened-human-workroom"
        code, receipt, raw = self.invoke(
            "--unpack-private-history-workroom", self.zipfile,
            "--private-workroom-output-dir", target, "--format", "json")
        self.assertEqual(code, 2)
        self.assertTrue(receipt["transport_integrity"])
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertTrue((target / "index.html").exists())
        self.assertIn("HOLD", (target / "index.html").read_text())
        self.assertNotIn(str(self.root), raw)

    def test_invalid_portable_blob_never_creates_recipient_directory(self):
        self.export()
        with ZipFile(self.zipfile, "a") as z:
            z.writestr("unauthorized-config.json", "{}")
        target = self.root / "absent-on-refusal"
        code, receipt, raw = self.invoke(
            "--unpack-private-history-workroom", self.zipfile,
            "--private-workroom-output-dir", target, "--format", "json")
        self.assertEqual(code, 2)
        self.assertFalse(receipt["transport_integrity"])
        self.assertFalse(target.exists())
        self.assertNotIn(str(self.root), raw)

    def test_two_exports_deterministic_and_not_bound_to_original_paths(self):
        first = self.export()
        other = self.root / "second-portable.zip"
        second = export_private_history_workroom(
            [str(self.snap1), str(self.snap2)], str(other)
        )
        self.assertEqual(first["transport_sha256"], second["transport_sha256"])
        self.assertEqual(self.zipfile.read_bytes(), other.read_bytes())
        self.assertNotIn(str(self.root).encode(), self.zipfile.read_bytes())

    def test_zip_trailing_or_prefixed_unlisted_secret_bytes_refused(self):
        self.export()
        actual = self.zipfile.read_bytes()
        for mutated in (
            actual + b"UNLISTED ORIGINAL PRIVATE SOURCE PAYLOAD",
            b"UNLISTED PRIVATE ORIGINAL PAYLOAD" + actual,
        ):
            self.zipfile.write_bytes(mutated)
            self.zipfile.chmod(0o600)
            target = self.root / "no-private-unpack"
            code, receipt, raw = self.invoke(
                "--unpack-private-history-workroom", self.zipfile,
                "--private-workroom-output-dir", target, "--format", "json")
            self.assertEqual(code, 2)
            self.assertIs(receipt["transport_integrity"], False)
            self.assertEqual(receipt["review_status"], "HOLD")
            self.assertFalse(target.exists())
            self.assertNotIn("UNLISTED ORIGINAL", raw)
        self.zipfile.write_bytes(actual)
        self.zipfile.chmod(0o600)
        self.assertTrue(verify_private_history_workroom(
            str(self.zipfile))["transport_integrity"])

    def test_rehashed_readme_approval_forgery_not_accepted(self):
        import stat
        self.export()
        with ZipFile(self.zipfile) as original:
            original_content = {name: original.read(name)
                                for name in original.namelist()}
        original_content["README.txt"] = (
            b"LightUp synthetic offline report.\n"
            b"Full security approval granted for external scanning!\n"
        )
        manifest = json.loads(original_content["transport-manifest.json"])
        manifest["files"]["README.txt"] = hashlib.sha256(
            original_content["README.txt"]).hexdigest()
        original_content["transport-manifest.json"] = json.dumps(
            manifest, separators=(",", ":")).encode() + b"\n"
        self.zipfile.unlink()
        with ZipFile(self.zipfile, "w") as archive:
            for name, data in sorted(original_content.items()):
                info = ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, data)
        self.zipfile.chmod(0o600)
        destination = self.root / "never-unpack-forged-approval"
        code, receipt, out = self.invoke(
            "--unpack-private-history-workroom", self.zipfile,
            "--private-workroom-output-dir", destination, "--format", "json")
        self.assertEqual(code, 2)
        self.assertIs(receipt["transport_integrity"], False)
        self.assertEqual(receipt["review_status"], "HOLD")
        self.assertFalse(destination.exists())
        self.assertNotIn("Full security approval", out)

    def test_additional_files_and_invalid_mode_refused(self):
        self.export()
        with ZipFile(self.zipfile, "a") as z:
            z.writestr("secrets.env", "not real")
        with self.assertRaises(ValueError):
            verify_private_history_workroom(str(self.zipfile))
        self.zipfile.chmod(0o644)
        with self.assertRaises(ValueError):
            verify_private_history_workroom(str(self.zipfile))


if __name__ == "__main__":
    unittest.main()
