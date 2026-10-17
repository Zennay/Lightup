"""Real disposable SQLite and CLI proof for #1561.

Strictly uses fake local grants with no network, customers or targets.
The inspected data file must remain byte-identical before/after every read.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.scope_grant_tenant_snapshot_1561 import (
    MAX_SNAPSHOT_BYTES, inspect_offline_grant_tenants, main,
)


class GrantTenantSnapshot1561(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="scope-1561-fake-")
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "fictional.sqlite"
        self.store = DomainStore(self.db)
        self.op = AccessContext("synthetic-operator", Role.OPERATOR)
        self.a = self.store.create_client(self.op, "Fictional Alpha")
        self.b = self.store.create_client(self.op, "Fictional Beta")
        self.ea = self.store.create_engagement(self.op, self.a.client_id, "Fake A")
        self.eb = self.store.create_engagement(self.op, self.b.client_id, "Fake B")
        now = datetime(2030, 8, 1, tzinfo=timezone.utc)
        self.scope = ScopeDefinition(assets=("127.0.0.1",),
                                     max_risk=RiskLevel.ANALYSIS_ONLY)
        self.window = (now - timedelta(days=1), now + timedelta(days=1))
        self.ga = self.grant(self.ea, "fictional-synthetic-A")
        self.gb = self.grant(self.eb, "fictional-synthetic-B")

    def grant(self, engagement, reference):
        return self.store.record_authorization_grant(
            self.op, engagement.engagement_id,
            "Fictional approvals only", reference, self.scope,
            *self.window,
        )

    def corrupt(self, sql, params):
        with sqlite3.connect(self.db) as con:
            con.execute(sql, params)

    def snapshot(self):
        return hashlib.sha256(self.db.read_bytes()).hexdigest()

    def audit(self):
        before = self.snapshot()
        result = inspect_offline_grant_tenants(str(self.db))
        self.assertEqual(before, self.snapshot(), "DB bytes mutated by inspector")
        for key in ("authorized", "consent_verified", "grants_allowed",
                    "scans_allowed", "dispatch_allowed", "merge_allowed",
                    "deploy_allowed", "release_allowed"):
            self.assertIs(result[key], False, key)
        return result

    def test_canonical_two_tenants_review_only_and_counted(self):
        r = self.audit()
        self.assertEqual((r["status"], r["reason"]), (
            "REVIEW_ONLY", "coherent_offline_snapshot"))
        self.assertEqual((r["coherent"], r["mismatch"], r["orphan"], r["total"]),
                         (2, 0, 0, 2))

    def test_wrong_tenant_mismatch_holds_and_does_not_leak(self):
        self.corrupt(
            "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
            (self.b.client_id, self.ga.grant_id),
        )
        r = self.audit()
        self.assertEqual(r["status"], "HOLD")
        self.assertEqual(r["reason"], "tenant_lineage_mismatch")
        self.assertEqual((r["coherent"], r["mismatch"], r["orphan"]), (1, 1, 0))
        wire = json.dumps(r)
        for secret in (self.a.client_id, self.b.client_id,
                       self.ga.grant_id, self.gb.grant_id,
                       self.ga.reference, self.gb.reference):
            self.assertNotIn(secret, wire)

    def test_orphan_holds_independently_of_tenant(self):
        self.corrupt(
            "UPDATE authorization_grants SET engagement_id=? WHERE grant_id=?",
            ("missing-fake-engagement", self.gb.grant_id),
        )
        r = self.audit()
        self.assertEqual(r["reason"], "orphaned_engagement")
        self.assertEqual((r["coherent"], r["orphan"]), (1, 1))

    def test_mixed_mismatch_orphan_holds(self):
        self.corrupt(
            "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
            (self.b.client_id, self.ga.grant_id),
        )
        self.corrupt(
            "UPDATE authorization_grants SET engagement_id=? WHERE grant_id=?",
            ("missing-fake-engagement", self.gb.grant_id),
        )
        r = self.audit()
        self.assertEqual(r["reason"], "orphaned_engagement")
        self.assertEqual((r["mismatch"], r["orphan"]), (1, 1))

    def test_null_and_binary_client_ids_hold(self):
        for value in (None, sqlite3.Binary(b"binary-fake-client")):
            with self.subTest(value=type(value).__name__):
                self.corrupt(
                    "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
                    (value, self.ga.grant_id),
                )
                self.assertEqual(self.audit()["reason"], "invalid_record")

    def test_sql_shaped_tenant_ids_are_inert(self):
        self.corrupt(
            "UPDATE authorization_grants SET client_id=? WHERE grant_id=?",
            ("' OR 1=1 -- FAKE", self.ga.grant_id),
        )
        self.assertEqual(self.audit()["reason"], "tenant_lineage_mismatch")

    def test_invalid_schema_missing_pk_holds(self):
        with sqlite3.connect(self.db) as con:
            con.execute("ALTER TABLE engagements RENAME TO deleted_engagements")
            con.execute("CREATE TABLE engagements(engagement_id TEXT, client_id TEXT)")
        self.assertEqual(self.audit()["reason"], "invalid_schema")

    def test_symlink_snapshot_holds(self):
        link = Path(self.temp.name) / "alias.sqlite"
        link.symlink_to(self.db)
        self.assertEqual(inspect_offline_grant_tenants(str(link))["status"], "HOLD")

    def test_companion_journal_wal_shm_holds(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(self.db) + suffix)
                sidecar.write_bytes(b"fake concurrent writer")
                self.assertEqual(self.audit()["reason"], "unsafe_snapshot")
                sidecar.unlink()

    def test_file_size_ceiling_holds_without_opening(self):
        with open(self.db, "r+b") as fd:
            fd.truncate(MAX_SNAPSHOT_BYTES + 1)
        self.assertEqual(inspect_offline_grant_tenants(str(self.db))["status"],
                         "HOLD")

    def test_directory_and_missing_path_hold(self):
        for p in (self.temp.name, str(Path(self.temp.name) / "missing.sqlite")):
            with self.subTest(p=p):
                self.assertEqual(inspect_offline_grant_tenants(p)["status"], "HOLD")

    def test_invalid_types_and_nul_hold(self):
        for bad in (None, b"x", 3, "", "a\x00b"):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(inspect_offline_grant_tenants(bad)["status"],
                                 "HOLD")

    def test_cli_success_never_exits_zero(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--offline-copy", str(self.db)])
        self.assertEqual(code, 3)
        r = json.loads(output.getvalue())
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertEqual(output.getvalue().count("\n"), 1)

    def test_cli_bad_args_never_exits_zero_and_no_path_leak(self):
        for args in ([], ["--allow"], ["--offline-copy"],
                     ["--offline-copy", str(self.db), "--authorize"]):
            with self.subTest(args=args):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(args)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")
                self.assertNotIn(str(self.db), output.getvalue())

    def test_real_module_subprocess_receipt(self):
        cmd = [sys.executable, "-m", "lightup.scope_grant_tenant_snapshot_1561",
               "--offline-copy", str(self.db)]
        environment = {**os.environ, "PYTHONPATH": str(
            Path(__file__).resolve().parents[1] / "src")}
        process = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, env=environment,
            check=False,
        )
        self.assertEqual(process.returncode, 3)
        self.assertEqual(json.loads(process.stdout)["status"], "REVIEW_ONLY")
        self.assertEqual(process.stderr, "")

    def test_no_socket_network_access(self):
        with patch("socket.socket", side_effect=AssertionError("network denied")):
            self.assertEqual(self.audit()["status"], "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
