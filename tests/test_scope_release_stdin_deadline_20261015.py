"""Real Linux subprocess tests for two wholly offline HOLD-only review readers."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = [
    ROOT / "scripts" / "scope_release_dependency_inventory_20261015.py",
    ROOT / "scripts" / "scope_release_dependency_nl_20261015.py",
]
FIXTURE = (ROOT / "docs" / "fixtures" / "scope-release-fictional-packet-20261015.json").read_bytes()


class ReleaseStdinDeadlineTests(unittest.TestCase):
    def launch(self, script, data, *, timeout=5):
        p = subprocess.run([sys.executable, str(script)], input=data,
                           capture_output=True, check=False, timeout=timeout)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, b"")
        self.assertIn(b"HOLD", p.stdout.upper() if "inventory" in script.name else b"HOLD")
        return p.stdout

    def hold_when_writer_leaves_pipe_open(self, script, data):
        start = time.monotonic()
        p = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            p.stdin.write(data)
            p.stdin.flush()
            p.wait(timeout=6)
            self.assertEqual(p.returncode, 2)
            output = p.stdout.read()
            errors = p.stderr.read()
            self.assertEqual(errors, b"")
            self.assertLess(time.monotonic() - start, 5.5)
            return output
        finally:
            for handle in (p.stdin, p.stdout, p.stderr):
                if handle is not None:
                    try:
                        handle.close()
                    except BrokenPipeError:
                        pass
            if p.poll() is None:
                p.kill()
                p.wait(timeout=2)

    def test_open_partial_pipe_times_out_to_generic_hold_both_clis(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                result = self.hold_when_writer_leaves_pipe_open(script, FIXTURE[:11])
                reference = self.launch(script, b"garbage")
                self.assertEqual(result, reference)

    def test_open_valid_complete_pipe_still_times_out_to_hold(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                result = self.hold_when_writer_leaves_pipe_open(script, FIXTURE)
                self.assertEqual(result, self.launch(script, b"garbage"))

    def test_fragmented_pipe_closed_after_last_fragment_matches_whole_input(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                p = subprocess.Popen([sys.executable, str(script)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    thirds = (FIXTURE[:13], FIXTURE[13:91], FIXTURE[91:])
                    for chunk in thirds:
                        p.stdin.write(chunk)
                        p.stdin.flush()
                        time.sleep(.015)
                    p.stdin.close()
                    p.wait(timeout=5)
                    self.assertEqual(p.returncode, 2)
                    self.assertEqual(p.stderr.read(), b"")
                    self.assertEqual(p.stdout.read(), self.launch(script, FIXTURE))
                finally:
                    for handle in (p.stdin, p.stdout, p.stderr):
                        if handle is not None and not handle.closed:
                            handle.close()
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=2)

    def test_oversize_open_pipe_denied_before_waiting_for_eof(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                start = time.monotonic()
                self.hold_when_writer_leaves_pipe_open(script, b"z" * 8193)
                self.assertLess(time.monotonic() - start, 2.0)

    def test_already_open_regular_input_file_is_supported(self):
        with tempfile.TemporaryFile(mode="w+b") as source:
            source.write(FIXTURE)
            source.seek(0)
            for script in SCRIPTS:
                with self.subTest(script=script.name):
                    source.seek(0)
                    p = subprocess.run([sys.executable, str(script)], stdin=source,
                                       capture_output=True, timeout=5)
                    self.assertEqual(p.returncode, 2)
                    self.assertEqual(p.stderr, b"")
                    self.assertEqual(p.stdout, self.launch(script, FIXTURE))

    def test_local_socket_stdin_denied_without_touching_peer(self):
        left, right = socket.socketpair()
        try:
            for script in SCRIPTS:
                with self.subTest(script=script.name):
                    p = subprocess.run([sys.executable, str(script)], stdin=left,
                                       capture_output=True, timeout=5)
                    self.assertEqual(p.returncode, 2)
                    self.assertEqual(p.stderr, b"")
                    self.assertEqual(p.stdout, self.launch(script, b"garbage"))
        finally:
            left.close()
            right.close()

    def test_character_device_stdin_denied(self):
        with open(os.devnull, "rb") as source:
            for script in SCRIPTS:
                with self.subTest(script=script.name):
                    p = subprocess.run([sys.executable, str(script)], stdin=source,
                                       capture_output=True, timeout=5)
                    self.assertEqual(p.returncode, 2)
                    self.assertEqual(p.stderr, b"")
                    self.assertEqual(p.stdout, self.launch(script, b"garbage"))

    def test_no_reader_mints_authority_from_self_reported_fixture(self):
        all_checked = {"schema": 1, "checks": {
            x: "SELF_REPORTED" for x in (
                "client_consent", "asset_and_capability_scope",
                "live_grant_and_revocation", "operator_step_up",
                "durable_prehandler_evidence", "installed_ingress_and_egress",
                "permanent_vps_ci", "independent_security_privacy_review",
                "explicit_human_release")}}
        raw = json.dumps(all_checked).encode()
        for script in SCRIPTS:
            output = self.launch(script, raw)
            self.assertIn(b"HOLD", output.upper())
            self.assertNotIn(b'"release_allowed":true', output)


if __name__ == "__main__":
    unittest.main()
