from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lightup import lab_bundle_inspect, lab_replay


class LabBundleInspectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._temporary.cleanup)
        cls.store = Path(cls._temporary.name) / "store"
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = lab_replay.main(["--store-dir", str(cls.store)])
        if exit_code != 0:
            raise AssertionError("synthetic loopback replay could not create a test bundle")
        receipt = json.loads(output.getvalue())
        cls.bundle = cls.store / receipt["receipt_sha256"]
        if not cls.bundle.is_dir():
            raise AssertionError("synthetic loopback replay did not publish its content-addressed bundle")

    def copy_bundle(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        destination = Path(temporary.name) / self.bundle.name
        shutil.copytree(self.bundle, destination)
        os.chmod(destination, 0o700)
        for entry in destination.iterdir():
            if entry.is_file() and not entry.is_symlink():
                os.chmod(entry, 0o600)
        return destination

    def test_valid_synthetic_bundle_passes_without_granting_authority(self) -> None:
        result = lab_bundle_inspect.inspect_bundle(str(self.bundle))
        self.assertEqual(result["integrity"], "PASS")
        self.assertEqual(result["profiles_matched"], 3)
        self.assertEqual(result["profiles_total"], 3)
        self.assertEqual(result["retests_passed"], 5)
        self.assertEqual(result["retests_total"], 5)
        self.assertIs(result["external_target_contacted"], False)
        self.assertIs(result["live_remediation_performed"], False)
        self.assertIs(result["production_authority_granted"], False)

    def test_entry_added_after_initial_directory_snapshot_is_rejected(self) -> None:
        bundle = self.copy_bundle()
        original_verify = lab_bundle_inspect._verify_databases

        def add_entry(database_fds, receipt):
            result = original_verify(database_fds, receipt)
            late_entry = bundle / "late-private-artifact"
            late_entry.write_text("not part of the original bundle", encoding="utf-8")
            os.chmod(late_entry, 0o600)
            return result

        with patch.object(lab_bundle_inspect, "_verify_databases", side_effect=add_entry):
            with self.assertRaisesRegex(RuntimeError, "bundle directory"):
                lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_entry_add_remove_cycle_during_verification_is_rejected(self) -> None:
        bundle = self.copy_bundle()
        original_verify = lab_bundle_inspect._verify_databases

        def transient_entry(database_fds, receipt):
            result = original_verify(database_fds, receipt)
            transient = bundle / "transient-private-artifact"
            transient.write_text("transient", encoding="utf-8")
            os.chmod(transient, 0o600)
            transient.unlink()
            return result

        with patch.object(lab_bundle_inspect, "_verify_databases", side_effect=transient_entry):
            with self.assertRaisesRegex(RuntimeError, "bundle directory changed"):
                lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_nonempty_sqlite_wal_is_rejected(self) -> None:
        bundle = self.copy_bundle()
        wal = bundle / "state.sqlite3-wal"
        wal.write_bytes(b"uncheckpointed")
        os.chmod(wal, 0o600)
        with self.assertRaisesRegex(ValueError, "WAL contains uncheckpointed data"):
            lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_receipt_table_replaced_by_equivalent_view_is_rejected(self) -> None:
        bundle = self.copy_bundle()
        with sqlite3.connect(bundle / "replay-ledger.sqlite3") as connection:
            connection.execute("ALTER TABLE replay_receipts RENAME TO receipt_shadow")
            connection.execute(
                "CREATE VIEW replay_receipts AS "
                "SELECT receipt_sha256,receipt_json FROM receipt_shadow"
            )
        with self.assertRaisesRegex(ValueError, "canonical replay schema"):
            lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_unreferenced_sqlite_table_is_rejected(self) -> None:
        bundle = self.copy_bundle()
        with sqlite3.connect(bundle / "replay-ledger.sqlite3") as connection:
            connection.execute("CREATE TABLE foreign_rows (payload TEXT)")
        with self.assertRaisesRegex(ValueError, "canonical replay schema"):
            lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_tampered_finding_asset_or_remediation_is_rejected(self) -> None:
        for column, forged_value in (
            ("asset", "https://untrusted.invalid/"),
            ("remediation", "forged remediation advice"),
        ):
            with self.subTest(column=column):
                bundle = self.copy_bundle()
                with sqlite3.connect(bundle / "domain.sqlite3") as connection:
                    connection.execute(
                        f"UPDATE findings SET {column}=?", (forged_value,)
                    )
                    connection.commit()
                    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                with self.assertRaisesRegex(ValueError, "finding identity mismatch"):
                    lab_bundle_inspect.inspect_bundle(str(bundle))

    def test_symlinked_bundle_path_is_rejected(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        alias = Path(temporary.name) / "bundle-alias"
        alias.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaises(OSError):
            lab_bundle_inspect.inspect_bundle(str(alias))

    def test_cli_failure_is_privacy_minimal(self) -> None:
        bundle = self.copy_bundle()
        unexpected = bundle / "unexpected-private-file"
        unexpected.write_text("private", encoding="utf-8")
        os.chmod(unexpected, 0o600)
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = lab_bundle_inspect.main(["--bundle-dir", str(bundle)])
        self.assertEqual(exit_code, 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["integrity"], "FAIL")
        self.assertNotIn(str(bundle), output.getvalue())
        self.assertNotIn("unexpected-private-file", output.getvalue())


if __name__ == "__main__":
    unittest.main()
