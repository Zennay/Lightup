"""Prove the optional NUMBER review CLI needs no socket allocation (#1143).

All child processes run from disposable source copies. A sitecustomize hook
runs before importing the CLI or its local modules and terminates on any socket
constructor, even if the CLI catches BaseException. This is a Python-level
regression tripwire, NOT an OS networking sandbox or execution authorization.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_CLI_PATH = "scripts/review_scope_finite_number_offline.py"
_PACKAGE_FILES = ("__init__.py", "finite_number_offline_review.py")
_MARKER = "def main(args: list[str]) -> int:\n"
# Constructor-level controls complement (but do not edit) the independent
# TCP/DNS/UDP call-level network tripwires in the original no-I/O test suite.
_PREIMPORT_TRIPWIRE = """import os
import socket

def _deny_socket(*_args, **_kwargs):
    os._exit(92)

socket.socket = _deny_socket
socket.socketpair = _deny_socket
socket.create_connection = _deny_socket
socket.create_server = _deny_socket
"""
_FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")


def _run_cli(repo: Path, injection: str, payload: bytes):
    with tempfile.TemporaryDirectory(prefix="lightup-socket-constructor-") as tmp:
        root = Path(tmp)
        (root / "scripts").mkdir()
        (root / "src" / "lightup").mkdir(parents=True)
        (root / "sitecustomize.py").write_text(_PREIMPORT_TRIPWIRE, encoding="utf-8")
        for name in _PACKAGE_FILES:
            shutil.copyfile(repo / "src" / "lightup" / name,
                            root / "src" / "lightup" / name)
        source = (repo / _CLI_PATH).read_text(encoding="utf-8")
        if source.count(_MARKER) != 1:
            raise AssertionError("real CLI entrypoint moved; review this regression")
        (root / _CLI_PATH).write_text(source.replace(_MARKER, _MARKER + injection),
                                     encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root)
        env["PYTHONNOUSERSITE"] = "1"
        env.pop("PYTHONPYCACHEPREFIX", None)
        proc = subprocess.run([sys.executable, "-B", str(root / _CLI_PATH)],
                              input=payload, cwd=root, env=env,
                              capture_output=True, check=False, timeout=12)
        return proc


class FiniteNumberCliSocketCreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[1]

    def test_canonical_review_and_invalid_hold_need_no_sockets(self):
        for raw, expected_code, expected_status in (
            (b'{"arguments":[["synthetic",1.25]]}', 3, "REVIEW_ONLY"),
            (b'{"arguments":[["synthetic",NaN]]}', 2, "HOLD"),
            (b'{"arguments":[["synthetic",1e999]]}', 2, "HOLD"),
            (b'{"arguments":[["synthetic",1e-999]]}', 2, "HOLD"),
        ):
            with self.subTest(raw=raw):
                result = _run_cli(self.repo, "", raw)
                self.assertEqual(result.returncode, expected_code, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(len(result.stdout.splitlines()), 1)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], expected_status)
                for flag in _FLAGS:
                    self.assertIs(receipt[flag], False, flag)

    def test_swallowed_socket_constructors_abort_before_any_allocation(self):
        # The mutated real CLI catches *all* Python exceptions. A catchable
        # RuntimeError-style hook could produce a false REVIEW_ONLY instead.
        constructors = (
            "socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
            "socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)",
            "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
            "socket.socketpair()",
            'socket.create_connection(("127.0.0.1", 9), timeout=0.1)',
            'socket.create_server(("127.0.0.1", 0))',
        )
        for statement in constructors:
            with self.subTest(statement=statement):
                injected = ("    import socket\n"
                            "    try:\n"
                            f"        {statement}\n"
                            "    except BaseException:\n"
                            "        pass\n")
                result = _run_cli(self.repo, injected,
                                  b'{"arguments":[["synthetic",1]]}')
                self.assertEqual(result.returncode, 92,
                                 "constructor attempt escaped the pre-import tripwire")
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
