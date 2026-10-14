"""Hermetic, offline process-boundary proof for finite NUMBER CLI (#1143).

Tests a real child interpreter against a seeded disposable SQLite and working
directory, with all direct socket/DNS operations forbidden by sitecustomize.
No production scope decisions, network targets, grants, or worker CI edits.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class FiniteNumberCliNoIoTests(unittest.TestCase):
    def test_no_workspace_mutation_or_network_for_success_hold_and_bad_args(self):
        repo = Path(__file__).resolve().parents[1]
        cli = repo / "scripts" / "review_scope_finite_number_offline.py"
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            (sandbox / "sitecustomize.py").write_text(
                "import socket\n"
                "def forbidden(*args, **kwargs):\n"
                "    raise RuntimeError('synthetic forbidden network operation')\n"
                "socket.socket.connect = forbidden\n"
                "socket.socket.connect_ex = forbidden\n"
                "socket.getaddrinfo = forbidden\n",
                encoding="utf-8",
            )
            (sandbox / "private-marker.txt").write_bytes(
                b"secret-synthetic-customer-should-not-be-written-or-echoed"
            )
            db = sandbox / "existing.sqlite"
            with sqlite3.connect(db) as con:
                con.execute("CREATE TABLE sentinel (id INTEGER PRIMARY KEY, marker TEXT)")
                con.execute("INSERT INTO sentinel (marker) VALUES (?)", ("existing-row",))

            def fingerprint() -> dict[str, str]:
                return {
                    str(path.relative_to(sandbox)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sandbox.rglob("*") if path.is_file()
                }

            def read_row() -> str:
                with sqlite3.connect(db) as con:
                    return con.execute("SELECT marker FROM sentinel WHERE id = 1").fetchone()[0]

            baseline = fingerprint()
            self.assertEqual(read_row(), "existing-row")
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PYTHONNOUSERSITE"] = "1"
            env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
            rows = [
                ([], b'{"arguments":[["count",2],["weight",0.125]]}', 3),
                ([], b'{"arguments":[["private",1e999]]}', 2),
                ([], b'{"arguments":[["private",NaN]]}', 2),
                ([], b'{"arguments":[["private",1e-999]]}', 2),
                ([], b'{"arguments":[["private",1],["private",2]]}', 2),
                ([], b'{"arguments":[["private",[[1]]]]}', 2),
                ([], b'{"arguments":[["private",' + b"9" * 2000 + b']]}', 2),
                ([], b'{"arguments":[["private",1]],"asset":"synthetic.invalid"}', 2),
                ([], b'{"arguments":[["private",2]]}' + b" " * 8193, 2),
                (["--forbidden"], b"", 2),
            ]
            for args, payload, expected_exit in rows:
                with self.subTest(args=args, payload_len=len(payload), marker=payload[:18]):
                    result = subprocess.run(
                        [sys.executable, "-B", str(cli), *args],
                        cwd=sandbox,
                        env=env,
                        input=payload,
                        capture_output=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, expected_exit, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(len(result.stdout.splitlines()), 1)
                    receipt = json.loads(result.stdout)
                    self.assertEqual(
                        receipt["status"], "REVIEW_ONLY" if expected_exit == 3 else "HOLD"
                    )
                    for flag in ("authorization_verified", "permit_issued",
                                 "execution_enabled", "merge_approved", "release_approved"):
                        self.assertIs(receipt[flag], False)
                    for secret in ("private", "secret-synthetic", "synthetic.invalid"):
                        self.assertNotIn(secret, result.stdout.decode("utf-8"))
                    self.assertEqual(read_row(), "existing-row")
                    self.assertEqual(fingerprint(), baseline)


if __name__ == "__main__":
    unittest.main()
