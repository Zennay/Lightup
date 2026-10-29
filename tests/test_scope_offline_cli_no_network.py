"""Hermetic subprocess regression probes for local-only scope registry CLIs.

Inject Python socket/DNS deny hooks *before* executing each real CLI entrypoint.
A visible marker records attempted network access, including attempts caught by
application code. These tests do not substitute for OS egress sandboxing.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lightup.capabilities import get_capabilities
from scripts.export_scope_capability_registry_offline import snapshot_manifest

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_MARKER = "__LIGHTUP_NETWORK_ATTEMPT_BLOCKED__"
_DENY_FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)

# No actual socket connects, DNS queries or target I/O. Hooks execute in each
# isolated child before the target's import or CLI main, not in this test process.
_INTERCEPT_AND_RUN = r"""
import os
import runpy
import socket
import sys

def deny(*args, **kwargs):
    sys.stderr.write("__LIGHTUP_NETWORK_ATTEMPT_BLOCKED__\n")
    raise RuntimeError("offline review network attempt rejected")

for name in (
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "getnameinfo",
    "create_connection",
):
    if hasattr(socket, name):
        setattr(socket, name, deny)
for name in (
    "connect", "connect_ex", "send", "sendall", "sendto",
):
    if hasattr(socket.socket, name):
        setattr(socket.socket, name, deny)

script = sys.argv[1]
arguments = sys.argv[2:]
sys.path.insert(0, os.path.dirname(script))
sys.argv = [script, *arguments]
runpy.run_path(script, run_name="__main__")
"""


def run_denied_network(script: str, *paths: str):
    proc = subprocess.run(
        [sys.executable, "-c", _INTERCEPT_AND_RUN, str(_SCRIPTS / script), *map(str, paths)],
        text=True, capture_output=True, timeout=15,
    )
    if _MARKER in proc.stderr:
        raise AssertionError(f"offline CLI attempted network: {script}")
    return proc


class LocalReviewNetworkBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.source = snapshot_manifest(get_capabilities())
        parsed = json.loads(self.source)
        parsed["capabilities"][0]["requires_explicit_activation"] = False
        self.modified = json.dumps(parsed, separators=(",", ":")).encode()

    def paths(self, folder, *payloads):
        result = []
        for index, payload in enumerate(payloads):
            path = Path(folder) / f"snapshot-{index}.json"
            path.write_bytes(payload)
            result.append(path)
        return result

    def assert_no_authority(self, data):
        for key in _DENY_FIELDS:
            self.assertIs(data[key], False, key)

    def test_real_source_export_never_attempts_network(self):
        proc = run_denied_network("export_scope_capability_registry_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), json.loads(self.source))

    def test_pairwise_equal_review_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.source)
            proc = run_denied_network("review_scope_capability_registry_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            receipt = json.loads(proc.stdout)
            self.assertEqual(receipt["status"], "REVIEW_ONLY")
            self.assert_no_authority(receipt)

    def test_pairwise_changed_review_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.modified)
            proc = run_denied_network("review_scope_capability_registry_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")

    def test_history_equal_review_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.source)
            proc = run_denied_network("review_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assert_no_authority(json.loads(proc.stdout))

    def test_history_midstream_change_reversion_no_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.modified, self.source)
            proc = run_denied_network("review_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(len(result["transitions"]), 2)
            self.assert_no_authority(result)

    def test_markdown_history_equal_without_socket(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.source)
            proc = run_denied_network("render_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertIn("REVIEW_ONLY", proc.stdout)
            self.assertIn("**Authority: NONE.**", proc.stdout)

    def test_markdown_history_hold_without_socket(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.modified)
            proc = run_denied_network("render_scope_registry_history_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("**Authority: NONE.**", proc.stdout)
            self.assertIn("HOLD", proc.stdout)

    def test_checkout_equal_real_source_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source, self.source)
            proc = run_denied_network("review_scope_history_against_checkout_offline.py", *paths)
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["latest_matches_local_registry"])
            self.assert_no_authority(json.loads(proc.stdout))

    def test_checkout_stale_manifest_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.modified, self.modified)
            proc = run_denied_network("review_scope_history_against_checkout_offline.py", *paths)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertFalse(json.loads(proc.stdout)["latest_matches_local_registry"])
            self.assert_no_authority(json.loads(proc.stdout))

    def test_incubation_real_source_never_attempts_network(self):
        proc = run_denied_network("review_scope_incubation_registry_offline.py")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "REVIEW_ONLY")
        self.assert_no_authority(json.loads(proc.stdout))

    def test_incubation_rejects_arguments_without_network(self):
        proc = run_denied_network("review_scope_incubation_registry_offline.py", "--active")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assert_no_authority(json.loads(proc.stdout))

    def test_same_file_alias_fails_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source)
            proc = run_denied_network("review_scope_registry_history_offline.py", paths[0], paths[0])
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["status"], "HOLD")
            self.assert_no_authority(json.loads(proc.stdout))

    def test_missing_file_fails_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source)
            absent = Path(folder) / "missing.json"
            proc = run_denied_network("review_scope_registry_history_offline.py", paths[0], absent)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assert_no_authority(json.loads(proc.stdout))

    def test_markdown_invalid_input_has_no_socket_and_denies(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = self.paths(folder, self.source)
            proc = run_denied_network("render_scope_registry_history_offline.py", paths[0], paths[0])
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("HOLD", proc.stdout)
            self.assertIn("**Authority: NONE.**", proc.stdout)


if __name__ == "__main__":
    unittest.main()
