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
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


# Exit immediately: a caught Python exception would falsely turn the test green.
# Sitecustomize is loaded before importing the script or its local packages.
_NETWORK_EXIT_TRIPWIRE = (
    "import os\n"
    "import socket\n"
    "import subprocess\n"
    "def forbidden(*args, **kwargs):\n"
    "    os._exit(92)\n"
    "socket.socket.connect = forbidden\n"
    "socket.socket.connect_ex = forbidden\n"
    "socket.getaddrinfo = forbidden\n"
    "subprocess.Popen = forbidden\n"
    "os.system = forbidden\n"
    "os.popen = forbidden\n"
)


class FiniteNumberCliNoIoTests(unittest.TestCase):
    def test_default_python_cannot_create_source_cache_in_disposable_copy(self):
        """Prove ordinary Python invocation is read-only without -B or env help."""
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            scripts = sandbox / "scripts"
            package = sandbox / "src" / "lightup"
            scripts.mkdir(parents=True)
            package.mkdir(parents=True)
            for source, destination in (
                (repo / "scripts" / "review_scope_finite_number_offline.py",
                 scripts / "review_scope_finite_number_offline.py"),
                (repo / "src" / "lightup" / "finite_number_offline_review.py",
                 package / "finite_number_offline_review.py"),
                (repo / "src" / "lightup" / "__init__.py",
                 package / "__init__.py"),
            ):
                shutil.copyfile(source, destination)
            cli = scripts / "review_scope_finite_number_offline.py"

            env = os.environ.copy()
            # Do not let host or previous CI process settings mask a bytecode write.
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            env.pop("PYTHONPYCACHEPREFIX", None)
            env["PYTHONNOUSERSITE"] = "1"
            env.pop("PYTHONPATH", None)

            def fingerprint() -> dict[str, str]:
                return {
                    str(p.relative_to(sandbox)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sandbox.rglob("*") if p.is_file()
                }

            baseline = fingerprint()
            for payload, exit_code in (
                (b'{"arguments":[["count",1]]}', 3),
                (b'{"arguments":[["count",NaN]]}', 2),
                (b'{"arguments":[["count",1e-999]]}', 2),
            ):
                with self.subTest(payload=payload[:28]):
                    result = subprocess.run(
                        [sys.executable, str(cli)],
                        cwd=sandbox,
                        env=env,
                        input=payload,
                        capture_output=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, exit_code, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    receipt = json.loads(result.stdout)
                    self.assertEqual(receipt["status"],
                                     "REVIEW_ONLY" if exit_code == 3 else "HOLD")
                    self.assertFalse(receipt["authorization_verified"])
                    self.assertFalse(receipt["permit_issued"])
                    self.assertFalse(receipt["execution_enabled"])
                    self.assertEqual(fingerprint(), baseline)
                    self.assertFalse(any(sandbox.rglob("*.pyc")))

    def test_default_interpreter_negative_control_creates_cache_without_guard(self):
        """The same real CLI must write .pyc when the single guard is removed."""
        repo = Path(__file__).resolve().parents[1]
        source = (repo / "scripts" / "review_scope_finite_number_offline.py").read_text(
            encoding="utf-8"
        )
        guard = "sys.dont_write_bytecode = True" + chr(10)
        self.assertEqual(source.count(guard), 1)
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            scripts = sandbox / "scripts"
            package = sandbox / "src" / "lightup"
            scripts.mkdir(parents=True)
            package.mkdir(parents=True)
            for relative in ("__init__.py", "finite_number_offline_review.py"):
                shutil.copyfile(repo / "src" / "lightup" / relative,
                                package / relative)
            mutant = scripts / "review_scope_finite_number_offline.py"
            mutant.write_text(source.replace(guard, ""), encoding="utf-8")
            env = os.environ.copy()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            env.pop("PYTHONPYCACHEPREFIX", None)
            env.pop("PYTHONPATH", None)
            env["PYTHONNOUSERSITE"] = "1"
            result = subprocess.run(
                [sys.executable, str(mutant)],
                cwd=sandbox,
                env=env,
                input=b'{"arguments":[["synthetic",1]]}',
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(json.loads(result.stdout)["status"], "REVIEW_ONLY")
            self.assertTrue(list(package.rglob("*.pyc")),
                            "test setup masks bytecode writes and cannot prove fix")

    def test_tripwire_kills_swallowed_dns_and_connect_in_actual_cli_copy(self):
        """Prove attempts cannot be swallowed while preserving REVIEW_ONLY."""
        repo = Path(__file__).resolve().parents[1]
        cli_source = (
            repo / "scripts" / "review_scope_finite_number_offline.py"
        ).read_text(encoding="utf-8")
        marker = "def main(args: list[str]) -> int:\n"
        self.assertEqual(cli_source.count(marker), 1)
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            scripts = sandbox / "scripts"
            package = sandbox / "src" / "lightup"
            scripts.mkdir(parents=True)
            package.mkdir(parents=True)
            (sandbox / "sitecustomize.py").write_text(
                _NETWORK_EXIT_TRIPWIRE, encoding="utf-8"
            )
            for relative in ("__init__.py", "finite_number_offline_review.py"):
                shutil.copyfile(
                    repo / "src" / "lightup" / relative, package / relative
                )
            mutated_cli = scripts / "review_scope_finite_number_offline.py"
            env = os.environ.copy()
            env["PYTHONPATH"] = root
            env["PYTHONNOUSERSITE"] = "1"
            for call in (
                'socket.getaddrinfo("never-resolve.invalid", 443)',
                'socket.socket().connect(("127.0.0.1", 9))',
                'socket.socket().connect_ex(("127.0.0.1", 9))',
            ):
                with self.subTest(call=call):
                    injection = (
                        "    import socket\n"
                        "    try:\n"
                        f"        {call}\n"
                        "    except BaseException:\n"
                        "        pass  # the former exception-only trap was bypassable\n"
                    )
                    mutated_cli.write_text(
                        cli_source.replace(marker, marker + injection),
                        encoding="utf-8",
                    )
                    result = subprocess.run(
                        [sys.executable, "-B", str(mutated_cli)],
                        cwd=sandbox,
                        env=env,
                        input=b'{"arguments":[["synthetic",1]]}',
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 92,
                        "attempt to call a network primitive was not caught",
                    )
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"")

    def test_tripwire_kills_swallowed_subprocess_and_shell_in_real_cli_copy(self):
        """No catchable error may hide Python child-process attempts."""
        repo = Path(__file__).resolve().parents[1]
        cli_source = (
            repo / "scripts" / "review_scope_finite_number_offline.py"
        ).read_text(encoding="utf-8")
        marker = "def main(args: list[str]) -> int:\n"
        self.assertEqual(cli_source.count(marker), 1)
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            scripts = sandbox / "scripts"
            package = sandbox / "src" / "lightup"
            scripts.mkdir(parents=True)
            package.mkdir(parents=True)
            (sandbox / "sitecustomize.py").write_text(
                _NETWORK_EXIT_TRIPWIRE, encoding="utf-8"
            )
            for relative in ("__init__.py", "finite_number_offline_review.py"):
                shutil.copyfile(
                    repo / "src" / "lightup" / relative, package / relative
                )
            mutated_cli = scripts / "review_scope_finite_number_offline.py"
            env = os.environ.copy()
            env["PYTHONPATH"] = root
            env["PYTHONNOUSERSITE"] = "1"
            calls = (
                'subprocess.Popen(["/bin/true"])',
                'subprocess.run(["/bin/true"], check=False)',
                'os.system("true")',
                'os.popen("true")',
            )
            for call in calls:
                with self.subTest(call=call):
                    injection = (
                        "    import os\n"
                        "    import subprocess\n"
                        "    try:\n"
                        f"        {call}\n"
                        "    except BaseException:\n"
                        "        pass  # cannot swallow uncatchable process tripwire\n"
                    )
                    mutated_cli.write_text(
                        cli_source.replace(marker, marker + injection),
                        encoding="utf-8",
                    )
                    result = subprocess.run(
                        [sys.executable, "-B", str(mutated_cli)],
                        cwd=sandbox,
                        env=env,
                        input=b'{"arguments":[["synthetic",1]]}',
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 92)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"")

    def test_no_workspace_mutation_or_network_for_success_hold_and_bad_args(self):
        repo = Path(__file__).resolve().parents[1]
        cli = repo / "scripts" / "review_scope_finite_number_offline.py"
        with tempfile.TemporaryDirectory() as root:
            sandbox = Path(root)
            (sandbox / "sitecustomize.py").write_text(
                _NETWORK_EXIT_TRIPWIRE,
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
            env["PYTHONPATH"] = root
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
