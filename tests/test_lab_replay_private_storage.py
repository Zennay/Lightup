from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path

from lightup.lab_replay import (
    _build_replay,
    _canonical,
    _prepare_store_dir,
    _require_private_artifact,
    _sha,
    _verify_database_lineage,
    _verify_existing_bundle,
)


class PrivateReplayStorageContract(unittest.TestCase):
    def test_owner_private_directory_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
            _require_private_artifact(directory, directory=True)

    def test_group_accessible_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "shared"
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o750)
            with self.assertRaises(PermissionError):
                _require_private_artifact(directory, directory=True)

    def test_owner_private_regular_file_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o600)
            _require_private_artifact(path, directory=False)

    def test_group_readable_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o640)
            with self.assertRaises(PermissionError):
                _require_private_artifact(path, directory=False)

    def test_hardlinked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            alias = Path(temporary) / "alias.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o600)
            os.link(path, alias)
            with self.assertRaises(PermissionError):
                _require_private_artifact(path, directory=False)

    def test_symlinked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target.json"
            link = Path(temporary) / "receipt.json"
            target.write_bytes(b"{}")
            os.chmod(target, 0o600)
            link.symlink_to(target)
            with self.assertRaises(PermissionError):
                _require_private_artifact(link, directory=False)

    def test_store_path_rejects_symlinked_parent_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / "real"
            real.mkdir(mode=0o700)
            os.chmod(real, 0o700)
            alias = Path(temporary) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(PermissionError):
                _prepare_store_dir(str(alias / "store"))

    def test_store_path_rejects_group_writable_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "shared"
            parent.mkdir(mode=0o700)
            os.chmod(parent, 0o770)
            store = parent / "store"
            with self.assertRaises(PermissionError):
                _prepare_store_dir(str(store))
            self.assertFalse(store.exists())

    def test_root_owned_sticky_tmp_ancestor_is_admitted(self) -> None:
        temporary_root = Path("/tmp")
        info = os.lstat(temporary_root)
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0 or not (mode & stat.S_ISVTX):
            self.skipTest("/tmp is not a root-owned sticky directory on this runner")
        with tempfile.TemporaryDirectory(dir=temporary_root) as temporary:
            store = Path(temporary) / "store"
            result = _prepare_store_dir(str(store))
            self.assertEqual(result, store.resolve())
            self.assertEqual(stat.S_IMODE(os.lstat(store).st_mode), 0o700)

    def test_existing_bundle_rejects_public_receipt_before_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir(mode=0o700)
            os.chmod(bundle, 0o700)
            receipt = b"{}"
            digest = hashlib.sha256(receipt).hexdigest()
            receipt_path = bundle / "receipt.json"
            receipt_path.write_bytes(receipt)
            os.chmod(receipt_path, 0o644)
            checksum = bundle / "receipt.sha256"
            checksum.write_text(f"{digest}  receipt.json\n", encoding="ascii")
            os.chmod(checksum, 0o600)
            with self.assertRaises(PermissionError):
                _verify_existing_bundle(bundle, receipt, digest)


    def test_replay_rejects_unreferenced_ledger_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _receipt_bytes, _digest = _build_replay(bundle)
            ledger_path = bundle / "replay-ledger.sqlite3"

            extra_event_payload = {"unexpected": "extra"}
            extra_event_json = _canonical(extra_event_payload).decode("utf-8")
            extra_event_id = _sha(_canonical({
                "event_type": "baseline", "payload": extra_event_payload
            }))
            with sqlite3.connect(ledger_path) as ledger:
                ledger.execute(
                    "INSERT INTO replay_events(event_id,event_type,payload_json) VALUES(?,?,?)",
                    (extra_event_id, "baseline", extra_event_json),
                )
            with self.assertRaisesRegex(RuntimeError, "event set does not match receipt"):
                _verify_database_lineage(bundle, receipt)

            extra_evidence_payload = {"unexpected": "extra"}
            extra_evidence_json = _canonical(extra_evidence_payload).decode("utf-8")
            extra_evidence_sha = _sha(extra_evidence_json.encode("utf-8"))
            with sqlite3.connect(ledger_path) as ledger:
                ledger.execute("DELETE FROM replay_events WHERE event_id=?", (extra_event_id,))
                ledger.execute(
                    "INSERT INTO replay_evidence"
                    "(evidence_sha256,evidence_kind,profile_id,payload_json) VALUES(?,?,?,?)",
                    (extra_evidence_sha, "baseline", "exposed", extra_evidence_json),
                )
            with self.assertRaisesRegex(RuntimeError, "evidence payload set does not match receipt"):
                _verify_database_lineage(bundle, receipt)


    def test_replay_receipt_table_view_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _raw, _digest = _build_replay(bundle)
            with sqlite3.connect(bundle / "replay-ledger.sqlite3") as connection:
                connection.execute("ALTER TABLE replay_receipts RENAME TO receipt_shadow")
                connection.execute(
                    "CREATE VIEW replay_receipts AS "
                    "SELECT receipt_sha256,receipt_json FROM receipt_shadow"
                )
            with self.assertRaisesRegex(RuntimeError, "SQLite schema is not canonical"):
                _verify_database_lineage(bundle, receipt)

    def test_replay_foreign_sqlite_table_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _raw, _digest = _build_replay(bundle)
            with sqlite3.connect(bundle / "replay-ledger.sqlite3") as connection:
                connection.execute("CREATE TABLE extra_evidence (value TEXT)")
            with self.assertRaisesRegex(RuntimeError, "SQLite schema is not canonical"):
                _verify_database_lineage(bundle, receipt)

    def test_forged_finding_asset_or_remediation_fails_reuse(self) -> None:
        for column, forged in (
            ("asset", "https://untrusted.invalid/"),
            ("remediation", "forged remediation action"),
        ):
            with self.subTest(column=column):
                with tempfile.TemporaryDirectory() as temporary:
                    bundle = Path(temporary)
                    receipt, _raw, _digest = _build_replay(bundle)
                    with sqlite3.connect(bundle / "domain.sqlite3") as domain:
                        domain.execute(f"UPDATE findings SET {column}=?", (forged,))
                    with self.assertRaisesRegex(RuntimeError, "source content does not match"):
                        _verify_database_lineage(bundle, receipt)

    def test_state_store_rejects_non_loopback_producer_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _receipt_bytes, _digest = _build_replay(bundle)
            state_path = bundle / "state.sqlite3"
            with sqlite3.connect(state_path) as state:
                row = state.execute(
                    "SELECT evidence_id,metadata_json FROM evidence "
                    "WHERE source='lab-http-baseline' LIMIT 1"
                ).fetchone()
            self.assertIsNotNone(row)
            evidence_id, raw_metadata = row
            metadata = json.loads(raw_metadata)
            metadata["asset"] = "http://example.com/"
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                    (_canonical(metadata).decode("utf-8"), evidence_id),
                )
            with self.assertRaisesRegex(
                RuntimeError, "producer evidence target is not the loopback fixture"
            ):
                _verify_database_lineage(bundle, receipt)

    def test_state_store_rejects_unreferenced_foreign_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _receipt_bytes, _digest = _build_replay(bundle)
            state_path = bundle / "state.sqlite3"
            with sqlite3.connect(state_path) as state:
                row = state.execute(
                    "SELECT run_id,capability_id,kind,sha256,metadata_json,created_at "
                    "FROM evidence WHERE source='lightup.lab_replay' LIMIT 1"
                ).fetchone()
            self.assertIsNotNone(row)
            run_id, capability_id, kind, digest, metadata, created_at = row
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "INSERT INTO evidence "
                    "(evidence_id,run_id,capability_id,kind,source,sha256,metadata_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    ("injected-foreign-source-evidence", run_id, capability_id, kind,
                     "untrusted.injected", digest, metadata, created_at),
                )
            with self.assertRaisesRegex(RuntimeError, "unexpected evidence source"):
                _verify_database_lineage(bundle, receipt)

    def test_state_store_rejects_unexpected_source_and_broken_run_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            receipt, _receipt_bytes, _digest = _build_replay(bundle)
            state_path = bundle / "state.sqlite3"
            with sqlite3.connect(state_path) as state:
                row = state.execute(
                    "SELECT evidence_id,run_id,capability_id,kind,source,sha256,metadata_json,created_at "
                    "FROM evidence WHERE source='lightup.lab_replay' "
                    "AND kind='fixture-baseline-observation' "
                    "AND metadata_json LIKE '%\"profile_id\":\"exposed\"%' LIMIT 1"
                ).fetchone()
            self.assertIsNotNone(row)
            evidence_id, run_id, capability_id, kind, source, digest, raw_meta, created_at = row

            with sqlite3.connect(state_path) as state:
                state.execute(
                    "INSERT INTO evidence "
                    "(evidence_id,run_id,capability_id,kind,source,sha256,metadata_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    ("injected-unreferenced-evidence", run_id, capability_id,
                     "unexpected-fixture-kind", source, digest, raw_meta, created_at),
                )
            with self.assertRaisesRegex(RuntimeError, "unexpected fixture evidence"):
                _verify_database_lineage(bundle, receipt)
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "DELETE FROM evidence WHERE evidence_id=?",
                    ("injected-unreferenced-evidence",),
                )

            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET source=? WHERE evidence_id=?",
                    ("untrusted.injected", evidence_id),
                )
            with self.assertRaisesRegex(RuntimeError, "unexpected evidence source"):
                _verify_database_lineage(bundle, receipt)
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET source=? WHERE evidence_id=?",
                    (source, evidence_id),
                )

            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                    ("untrusted.capability", evidence_id),
                )
            with self.assertRaisesRegex(RuntimeError, "capability does not match"):
                _verify_database_lineage(bundle, receipt)
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                    (capability_id, evidence_id),
                )

            with sqlite3.connect(state_path) as state:
                retest_row = state.execute(
                    "SELECT evidence_id,run_id FROM evidence "
                    "WHERE source='lightup.lab_replay' "
                    "AND kind='fixture-retest-observation' LIMIT 1"
                ).fetchone()
            self.assertIsNotNone(retest_row)
            retest_evidence_id, retest_run_id = retest_row
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET run_id=? WHERE evidence_id=?",
                    ("missing-run-id", retest_evidence_id),
                )
            with self.assertRaisesRegex(RuntimeError, "not bound to exposed baseline run"):
                _verify_database_lineage(bundle, receipt)
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET run_id=? WHERE evidence_id=?",
                    (retest_run_id, retest_evidence_id),
                )

            metadata = json.loads(raw_meta)
            duplicate_key_metadata = (
                '{"fixture_sha256":' + json.dumps(metadata["fixture_sha256"])
                + ',"profile_id":' + json.dumps(metadata["profile_id"])
                + ',"profile_id":' + json.dumps(metadata["profile_id"]) + '}'
            )
            with sqlite3.connect(state_path) as state:
                state.execute(
                    "UPDATE evidence SET metadata_json=? WHERE evidence_id=?",
                    (duplicate_key_metadata, evidence_id),
                )
            with self.assertRaisesRegex(RuntimeError, "metadata is invalid or non-canonical"):
                _verify_database_lineage(bundle, receipt)


if __name__ == "__main__":
    unittest.main()
