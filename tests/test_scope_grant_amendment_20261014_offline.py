"""Synthetic/offline contracts for non-authorizing grant amendment comparison."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "review_scope_grant_amendment_20261014_offline.py"
spec = importlib.util.spec_from_file_location("grant_amendment_review", SCRIPT)
reviewer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(reviewer)


def fixture():
    grant = {
        "grant_id": "grant-demo-01",
        "client_id": "client-demo",
        "engagement_id": "eng-demo",
        "approved_by": "operator-demo",
        "reference": "reference-demo",
        "assets": ["lab-a.example", "lab-b.example"],
        "excluded_assets": ["lab-b.example"],
        "capabilities": ["http_headers", "tls_baseline"],
        "max_risk": 3,
        "valid_from": "2026-10-14T00:00:00Z",
        "valid_until": "2026-10-15T00:00:00Z",
        "recurring_retest_allowed": False,
    }
    return {"schema": "lightup.grant-amendment-review.v1", "before": copy.deepcopy(grant), "after": copy.deepcopy(grant)}


def encode(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class GrantAmendmentOfflineTests(unittest.TestCase):
    def assert_denied_authority(self, receipt, code):
        self.assertIn(code, (2, 3))
        self.assertIn(receipt["status"], ("HOLD", "REVIEW_ONLY"))
        for flag in (
            "authorized", "permit_issued", "dispatch_enabled",
            "merge_approved", "deploy_approved", "release_approved",
        ):
            self.assertIs(receipt[flag], False)

    def test_unchanged_review_only_no_permission(self):
        out, code = reviewer.review(encode(fixture()))
        self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
        self.assertEqual(out["widening_dimensions"], [])
        self.assert_denied_authority(out, code)

    def test_genuine_multidimensional_narrowing(self):
        value = fixture()
        value["after"].update({
            "assets": ["lab-a.example"],
            "excluded_assets": ["lab-b.example", "lab-c.example"],
            "capabilities": ["tls_baseline"],
            "max_risk": 1,
            "valid_from": "2026-10-14T06:00:00Z",
            "valid_until": "2026-10-14T09:00:00Z",
        })
        out, code = reviewer.review(encode(value))
        self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(out, code)

    def test_each_widening_dimension_refused(self):
        changes = [
            ("grant_id", "grant-other", "identity"),
            ("client_id", "client-other", "identity"),
            ("engagement_id", "eng-other", "identity"),
            ("approved_by", "untrusted-operator", "identity"),
            ("reference", "reference-other", "identity"),
            ("assets", ["lab-a.example", "lab-b.example", "lab-c.example"], "assets"),
            ("excluded_assets", [], "exclusions"),
            ("capabilities", ["http_headers", "tls_baseline", "new_tool"], "capabilities"),
            ("max_risk", 4, "risk"),
            ("valid_from", "2026-10-13T00:00:00Z", "window"),
            ("valid_until", "2026-10-16T00:00:00Z", "window"),
            ("recurring_retest_allowed", True, "recurring_retest"),
        ]
        for name, value, dimension in changes:
            with self.subTest(name=name):
                case = fixture()
                case["after"][name] = value
                out, code = reviewer.review(encode(case))
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertIn(dimension, out["widening_dimensions"])
                self.assert_denied_authority(out, code)

    def test_atomic_multi_widening(self):
        value = fixture()
        value["after"]["max_risk"] = 4
        value["after"]["assets"].append("new.example")
        value["after"]["recurring_retest_allowed"] = True
        out, code = reviewer.review(encode(value))
        self.assertEqual(out["widening_dimensions"], ["assets", "recurring_retest", "risk"])
        self.assertEqual(code, 2)

    def test_malformed_primitive_type_and_shape_hold(self):
        bad_values = [
            (("after", "max_risk"), True),
            (("after", "max_risk"), 1.0),
            (("after", "max_risk"), -1),
            (("after", "max_risk"), 5),
            (("after", "recurring_retest_allowed"), 1),
            (("after", "assets"), "lab.example"),
            (("after", "capabilities"), []),
            (("before", "assets"), "not-a-list"),
            (("after", "assets"), ["lab-a.example", "lab-a.example"]),
            (("after", "assets"), ["UPPERCASE.example"]),
            (("after", "grant_id"), ""),
            (("after", "grant_id"), ["x"]),
            (("after", "valid_from"), "2026-10-14"),
            (("after", "valid_from"), "2026-10-14T00:00:00+00:00"),
            (("after", "valid_from"), "2026-02-30T00:00:00Z"),
            (("after", "valid_until"), "2026-10-14T00:00:00Z"),
        ]
        for path, replacement in bad_values:
            with self.subTest(path=path, value=replacement):
                case = fixture()
                case[path[0]][path[1]] = replacement
                out, code = reviewer.review(encode(case))
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assert_denied_authority(out, code)

    def test_extra_or_missing_fields_fail(self):
        cases = []
        x = fixture()
        x["after"]["authorized"] = True
        cases.append(x)
        y = fixture()
        del y["before"]["client_id"]
        cases.append(y)
        z = fixture()
        z["trusted"] = True
        cases.append(z)
        for case in cases:
            out, code = reviewer.review(encode(case))
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_duplicate_json_keys_including_decoded_alias(self):
        for raw in (
            b'{"schema":"x","schema":"x","before":{},"after":{}}',
            b'{"schema":"lightup.grant-amendment-review.v1","before":{"assets":[],"\\u0061ssets":[]},"after":{}}',
        ):
            out, code = reviewer.review(raw)
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_untrusted_bytes_never_raise_or_echo(self):
        inputs = [
            b"", b"\xff", b"\xef\xbb\xbf{}", b"null", b"{}{}",
            b"NaN", b"1e999", b"[]", b" " * (reviewer.MAX_INPUT + 1),
            b"{", b"\x00", b'{"secret":"do-not-print-this"}',
        ]
        for data in inputs:
            with self.subTest(data=data[:15]):
                out, code = reviewer.review(data)
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertNotIn("do-not-print-this", json.dumps(out))
                self.assert_denied_authority(out, code)

    def test_wrong_input_python_types_fail_closed(self):
        for data in ("{}", bytearray(b"{}"), None, 5, True):
            out, code = reviewer.review(data)
            self.assertEqual((out["status"], code), ("HOLD", 2))

    def test_repeated_deterministic_and_caller_unchanged(self):
        value = fixture()
        original = copy.deepcopy(value)
        a = reviewer.review(encode(value))
        b = reviewer.review(encode(value))
        self.assertEqual(a, b)
        self.assertEqual(value, original)

    def test_script_has_no_runtime_authorization_import(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("from lightup", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("urllib.request", source)

    def test_real_subprocess_narrowing_is_nonzero_and_opaque(self):
        raw = encode(fixture())
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            input=raw, capture_output=True, check=False, timeout=8,
        )
        self.assertEqual(result.returncode, 3)
        receipt = json.loads(result.stdout)
        self.assert_denied_authority(receipt, result.returncode)
        self.assertNotIn(b"grant-demo-01", result.stdout)
        self.assertNotIn(b"client-demo", result.stdout)
        self.assertNotIn(b"lab-a.example", result.stdout)
        self.assertFalse(result.stderr)

    def test_real_subprocess_widening_is_nonzero_and_opaque(self):
        value = fixture()
        value["after"]["assets"] = ["lab-a.example", "new.example"]
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            input=encode(value), capture_output=True, check=False, timeout=8,
        )
        self.assertEqual(result.returncode, 2)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["widening_dimensions"], ["assets"])
        self.assert_denied_authority(receipt, result.returncode)

    def test_subprocess_complete_but_unclosed_fifo_fails_finitely(self):
        process = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            process.stdin.write(encode(fixture()))
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=7), 2)
            out = process.stdout.read()
            receipt = json.loads(out)
            self.assertEqual(receipt["status"], "HOLD")
            self.assert_denied_authority(receipt, process.returncode)
            self.assertNotIn(b"grant-demo", out)
            self.assertFalse(process.stderr.read())
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_subprocess_partial_unclosed_fifo_fails_finitely(self):
        process = subprocess.Popen(
            [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            process.stdin.write(b'{"schema":"do-not-echo')
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=7), 2)
            out = process.stdout.read()
            self.assertEqual(json.loads(out)["status"], "HOLD")
            self.assertNotIn(b"do-not-echo", out)
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_subprocess_redirected_bounded_regular_file_is_reviewable(self):
        with tempfile.TemporaryFile() as source:
            source.write(encode(fixture()))
            source.seek(0)
            result = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=source, capture_output=True, check=False, timeout=8,
            )
        self.assertEqual(result.returncode, 3)
        self.assert_denied_authority(json.loads(result.stdout), result.returncode)

    @unittest.skipUnless(hasattr(socket, "socketpair") and os.name == "posix", "POSIX local socket")
    def test_subprocess_socket_stdin_refused_without_read(self):
        source, sink = socket.socketpair()
        try:
            with source, sink:
                result = subprocess.run(
                    [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                    stdin=sink, capture_output=True, check=False, timeout=8,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
        finally:
            source.close()
            sink.close()

    def test_denial_flags_are_immutable(self):
        with self.assertRaises(TypeError):
            reviewer.DENIAL["authorized"] = True
        with self.assertRaises(TypeError):
            reviewer.DENIAL["release_approved"] = True
        self.assertIs(reviewer.review(encode(fixture()))[0]["authorized"], False)

    def test_all_128_synthetic_widening_combinations_have_zero_authority(self):
        # 7 orthogonal widening dimensions; any chosen bit requires HOLD.
        for bits in range(128):
            item = fixture()
            after = item["after"]
            if bits & 1:
                after["grant_id"] = "other-grant"
            if bits & 2:
                after["assets"].append("new.example")
            if bits & 4:
                after["excluded_assets"] = []
            if bits & 8:
                after["capabilities"].append("other_tool")
            if bits & 16:
                after["max_risk"] = 4
            if bits & 32:
                after["valid_until"] = "2026-10-16T00:00:00Z"
            if bits & 64:
                after["recurring_retest_allowed"] = True
            receipt, code = reviewer.review(encode(item))
            with self.subTest(bits=bits):
                self.assert_denied_authority(receipt, code)
                if bits:
                    self.assertEqual((receipt["status"], code), ("HOLD", 2))
                else:
                    self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))

    def test_sealed_receipt_exact_schema_never_forges_authority(self):
        accepted = [reviewer.review(encode(fixture()))[0]]
        changed = fixture()
        changed["after"]["max_risk"] = 4
        accepted.append(reviewer.review(encode(changed))[0])
        accepted.append(reviewer.review(b"broken")[0])
        for receipt in accepted:
            data = reviewer._seal_receipt(receipt)
            self.assertIs(type(data), bytes)
            self.assertLessEqual(len(data), reviewer.MAX_OUTPUT)
            self.assertEqual(data.count(b"\n"), 1)
            self.assertTrue(data.endswith(b"\n"))
            self.assertTrue(data.isascii())
            self.assertEqual(json.loads(data), receipt)
            self.assertNotIn(b"grant-demo", data)
            self.assertNotIn(b"operator-demo", data)

        original, _ = reviewer.review(encode(fixture()))
        for key, replacement in (
            ("authorized", True),
            ("permit_issued", 0),
            ("dispatch_enabled", "false"),
            ("release_approved", True),
            ("schema", "different"),
            ("status", "AUTHORIZED"),
            ("status", True),
            ("reason", "approved"),
            ("widening_dimensions", ["unknown"]),
            ("widening_dimensions", ["risk", "risk"]),
            ("widening_dimensions", ["risk"]),
        ):
            forged = dict(original)
            forged[key] = replacement
            with self.subTest(key=key, replacement=replacement):
                self.assertIsNone(reviewer._seal_receipt(forged))
        for mutation in ("extra", "missing"):
            forged = dict(original)
            if mutation == "extra":
                forged["secret"] = "MUST-NOT-OUTPUT"
            else:
                del forged["merge_approved"]
            self.assertIsNone(reviewer._seal_receipt(forged))

    def test_regular_file_stdout_is_rejected_without_writing(self):
        with tempfile.TemporaryFile() as sink:
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encode(fixture()), stdout=sink, stderr=subprocess.PIPE,
                timeout=8, check=False,
            )
            sink.seek(0)
            self.assertEqual(sink.read(), b"")
        self.assertEqual(child.returncode, 2)
        self.assertFalse(child.stderr)

    @unittest.skipUnless(hasattr(socket, "socketpair") and os.name == "posix", "POSIX socketpair")
    def test_inherited_socket_stdout_refused_without_writing(self):
        source, sink = socket.socketpair()
        try:
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encode(fixture()), stdout=sink,
                stderr=subprocess.PIPE, timeout=8, check=False,
            )
            self.assertEqual(child.returncode, 2)
            self.assertFalse(child.stderr)
            sink.close()
            source.settimeout(3)
            self.assertEqual(source.recv(2048), b"")
        finally:
            source.close()
            sink.close()

    @unittest.skipUnless(os.name == "posix", "POSIX pipe flags")
    def test_successful_child_receipt_restores_parent_pipe_mode(self):
        read_fd, write_fd = os.pipe()
        try:
            self.assertTrue(os.get_blocking(write_fd))
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encode(fixture()), stdout=write_fd,
                stderr=subprocess.PIPE, check=False, timeout=8,
            )
            self.assertEqual(child.returncode, 3)
            self.assertFalse(child.stderr)
            self.assertTrue(os.get_blocking(write_fd))
            output = os.read(read_fd, 512)
            self.assertEqual(json.loads(output)["status"], "REVIEW_ONLY")
            self.assertEqual(output.count(b"\n"), 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    @unittest.skipUnless(os.name == "posix", "POSIX pipe flags")
    def test_full_inherited_stdout_returns_finitely_and_restores_parent_mode(self):
        read_fd, write_fd = os.pipe()
        try:
            os.set_blocking(write_fd, False)
            try:
                while True:
                    os.write(write_fd, b"X" * 4096)
            except BlockingIOError:
                pass
            os.set_blocking(write_fd, True)
            self.assertTrue(os.get_blocking(write_fd))
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                input=encode(fixture()), stdout=write_fd,
                stderr=subprocess.PIPE, check=False, timeout=8,
            )
            self.assertEqual(child.returncode, 2)
            self.assertFalse(child.stderr)
            self.assertTrue(os.get_blocking(write_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    @unittest.skipUnless(os.name == "posix", "POSIX inherited fd test")
    def test_pipe_stdin_restores_parent_reader_blocking_mode(self):
        reader, writer = os.pipe()
        try:
            self.assertTrue(os.get_blocking(reader))
            process = subprocess.Popen(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=reader, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            os.write(writer, encode(fixture()))
            os.close(writer)
            writer = -1
            output, errors = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 3)
            self.assertFalse(errors)
            self.assertEqual(json.loads(output)["status"], "REVIEW_ONLY")
            self.assertTrue(os.get_blocking(reader))
        finally:
            os.close(reader)
            if writer != -1:
                os.close(writer)

    def test_input_file_metadata_drift_is_atomically_refused(self):
        original = SimpleNamespace(
            st_mode=stat.S_IFREG, st_dev=15, st_ino=22, st_size=2,
            st_mtime_ns=100, st_ctime_ns=100,
        )
        class Stdin:
            def fileno(self):
                return 0
        for changed_field in ("st_dev", "st_ino", "st_mode", "st_size",
                              "st_mtime_ns", "st_ctime_ns"):
            after = SimpleNamespace(**vars(original))
            setattr(after, changed_field, (
                stat.S_IFIFO if changed_field == "st_mode"
                else getattr(after, changed_field) + 1
            ))
            with self.subTest(changed=changed_field):
                with patch.object(reviewer.sys, "stdin", Stdin()), \
                     patch.object(reviewer.os, "fstat", side_effect=[original, after]), \
                     patch.object(reviewer.os, "lseek", return_value=0), \
                     patch.object(reviewer.os, "get_blocking", return_value=False), \
                     patch.object(reviewer.select, "select", return_value=([0], [], [])), \
                     patch.object(reviewer.os, "read", side_effect=[b"{}", b""]):
                    self.assertEqual(reviewer._bounded_stdin(), b"")

    def test_input_metadata_stability_accepts_bounded_read(self):
        original = SimpleNamespace(
            st_mode=stat.S_IFREG, st_dev=15, st_ino=22, st_size=2,
            st_mtime_ns=100, st_ctime_ns=100,
        )
        class Stdin:
            def fileno(self):
                return 0
        with patch.object(reviewer.sys, "stdin", Stdin()), \
             patch.object(reviewer.os, "fstat", side_effect=[original, original]), \
             patch.object(reviewer.os, "lseek", return_value=0), \
             patch.object(reviewer.os, "get_blocking", return_value=False), \
             patch.object(reviewer.select, "select", return_value=([0], [], [])), \
             patch.object(reviewer.os, "read", side_effect=[b"{}", b""]):
            self.assertEqual(reviewer._bounded_stdin(), b"{}")

    def test_input_nonblocking_flag_restored_even_on_setter_error(self):
        original = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=15,
                                   st_ino=22, st_size=0)
        class Stdin:
            def fileno(self):
                return 0
        for errors in ((OSError("setter-error"), None), (None, OSError("restore-error"))):
            with self.subTest(errors=repr(errors)):
                def change_mode(*_args):
                    outcome = errors[change_mode.calls]
                    change_mode.calls += 1
                    if outcome:
                        raise outcome
                change_mode.calls = 0
                with patch.object(reviewer.sys, "stdin", Stdin()), \
                     patch.object(reviewer.os, "fstat", side_effect=[original, original]), \
                     patch.object(reviewer.os, "get_blocking", return_value=True), \
                     patch.object(reviewer.os, "set_blocking", side_effect=change_mode), \
                     patch.object(reviewer.select, "select", return_value=([0], [], [])), \
                     patch.object(reviewer.os, "read", side_effect=[b"{}", b""]):
                    self.assertEqual(reviewer._bounded_stdin(), b"")
                self.assertEqual(change_mode.calls, 2)

    @unittest.skipUnless(os.name == "posix", "POSIX inherited local pipe")
    def test_invalid_cli_arguments_do_not_echo_secrets_or_read_unclosed_stdin(self):
        cases = (
            [],
            ["--help"],
            ["--stdin-json", "--stdin-json"],
            ["--stdin-json", "--unexpected", "SUPER-SECRET-123"],
            ["--unexpected", "SUPER-SECRET-123"],
        )
        for args in cases:
            with self.subTest(args=args):
                reader, writer = os.pipe()
                process = None
                try:
                    # Prefill before spawning, but never close the writer.
                    # Any unauthorized stdin read either consumes a secret or
                    # blocks on EOF; correct CLI rejection does neither.
                    os.write(writer, b"SUPER-SECRET-FROM-PIPE")
                    process = subprocess.Popen(
                        [sys.executable, "-B", str(SCRIPT), *args],
                        stdin=reader, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertEqual(process.wait(timeout=5), 2)
                    self.assertEqual(process.stdout.read(), b"")
                    self.assertEqual(process.stderr.read(), b"")
                finally:
                    if process is not None:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=5)
                        process.stdout.close()
                        process.stderr.close()
                    os.close(reader)
                    os.close(writer)

    def test_direct_cli_argv_shape_noncanonical_types_refused(self):
        for bad in ("--stdin-json", (), True, ["--stdin-json", "--stdin-json"],
                    ["--bad"], [True], [b"--stdin-json"]):
            with self.subTest(argument=bad):
                self.assertEqual(reviewer.main(bad), 2)

    def test_live_model_membership_agrees_with_synthetic_narrowing(self):
        # Real production model constructors/decision *predicates*, but no
        # real grant issuance, persistence, executor, handler or target I/O.
        from datetime import datetime, timezone
        from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition

        packet = fixture()
        packet["after"]["assets"] = ["lab-a.example"]
        packet["after"]["capabilities"] = ["tls_baseline"]
        packet["after"]["excluded_assets"] = ["lab-b.example", "lab-a.example"]
        packet["after"]["max_risk"] = 1
        packet["after"]["valid_from"] = "2026-10-14T06:00:00Z"
        packet["after"]["valid_until"] = "2026-10-14T09:00:00Z"
        self.assertEqual(reviewer.review(encode(packet))[1], 3)

        def to_grant(d):
            start = datetime.fromisoformat(d["valid_from"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(d["valid_until"].replace("Z", "+00:00"))
            return AuthorizationGrant(
                grant_id=d["grant_id"], client_id=d["client_id"],
                engagement_id=d["engagement_id"], approved_by=d["approved_by"],
                reference=d["reference"],
                scope=ScopeDefinition(
                    assets=tuple(d["assets"]), excluded_assets=tuple(d["excluded_assets"]),
                    allowed_capabilities=tuple(d["capabilities"]),
                    max_risk=RiskLevel(d["max_risk"]),
                ),
                valid_from=start, valid_until=end,
                recurring_retest_allowed=d["recurring_retest_allowed"],
            )
        old = to_grant(packet["before"])
        new = to_grant(packet["after"])
        evaluation = datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc)
        self.assertTrue(old.is_current(evaluation))
        self.assertTrue(new.is_current(evaluation))
        for asset in ("lab-a.example", "lab-b.example", "unlisted.example"):
            self.assertFalse(
                new.scope.allows_asset(asset) and not old.scope.allows_asset(asset),
                msg="canonical synthetic narrowed asset unexpectedly gained real-model permission",
            )
        for capability in ("tls_baseline", "http_headers", "unknown"):
            self.assertFalse(
                new.scope.allows_capability(capability)
                and not old.scope.allows_capability(capability),
            )
        self.assertLessEqual(new.scope.max_risk, old.scope.max_risk)
        self.assertLessEqual(old.valid_from, new.valid_from)
        self.assertLessEqual(new.valid_until, old.valid_until)

    def test_input_silent_mode_setter_failure_refuses_review_bytes(self):
        class Stdin:
            def fileno(self):
                return 0
        original = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=2, st_ino=7, st_size=0)
        with patch.object(reviewer.sys, "stdin", Stdin()), \
             patch.object(reviewer.os, "fstat", side_effect=[original, original]), \
             patch.object(reviewer.os, "get_blocking", side_effect=[True, False]), \
             patch.object(reviewer.os, "set_blocking") as setter, \
             patch.object(reviewer.select, "select", return_value=([0], [], [])), \
             patch.object(reviewer.os, "read", side_effect=[b"{}", b""]):
            self.assertEqual(reviewer._bounded_stdin(), b"")
        self.assertEqual(setter.call_count, 2)

    def test_output_silent_mode_setter_failure_refuses_receipt(self):
        class Stdout:
            def fileno(self):
                return 1
        sink = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=2, st_ino=7)
        receipt, _ = reviewer.review(encode(fixture()))
        with patch.object(reviewer.sys, "stdout", Stdout()), \
             patch.object(reviewer.os, "fstat", return_value=sink), \
             patch.object(reviewer.os, "get_blocking", side_effect=[True, False]), \
             patch.object(reviewer.os, "set_blocking") as setter, \
             patch.object(reviewer.select, "select", return_value=([], [1], [])), \
             patch.object(reviewer.os, "write", side_effect=lambda _, data: len(data)):
            self.assertFalse(reviewer._emit_receipt(receipt))
        self.assertEqual(setter.call_count, 2)

    def test_stdout_changed_device_or_inode_cannot_receive_receipt(self):
        class Stdout:
            def fileno(self):
                return 1
        before = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=2, st_ino=7)
        for dimension in ("st_dev", "st_ino", "st_mode"):
            after = SimpleNamespace(**vars(before))
            setattr(after, dimension, (
                stat.S_IFSOCK if dimension == "st_mode"
                else getattr(after, dimension) + 1
            ))
            receipt, _ = reviewer.review(encode(fixture()))
            with self.subTest(dimension=dimension):
                with patch.object(reviewer.sys, "stdout", Stdout()), \
                     patch.object(reviewer.os, "fstat", side_effect=[before, after]), \
                     patch.object(reviewer.os, "get_blocking", return_value=True), \
                     patch.object(reviewer.os, "set_blocking"), \
                     patch.object(reviewer.select, "select", return_value=([], [1], [])), \
                     patch.object(reviewer.os, "write") as writer:
                    self.assertFalse(reviewer._emit_receipt(receipt))
                writer.assert_not_called()

    def test_stdout_unchanged_identity_still_emits_only_sealed_receipt(self):
        class Stdout:
            def fileno(self):
                return 1
        sink = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=2, st_ino=7)
        receipt, _ = reviewer.review(encode(fixture()))
        wire: list[bytes] = []
        def send(_fd, data):
            wire.append(bytes(data))
            return len(data)
        with patch.object(reviewer.sys, "stdout", Stdout()), \
             patch.object(reviewer.os, "fstat", return_value=sink), \
             patch.object(reviewer.os, "get_blocking", return_value=True), \
             patch.object(reviewer.os, "set_blocking"), \
             patch.object(reviewer.select, "select", return_value=([], [1], [])), \
             patch.object(reviewer.os, "write", side_effect=send):
            self.assertTrue(reviewer._emit_receipt(receipt))
        self.assertEqual(b"".join(wire), reviewer._seal_receipt(receipt))

    def test_short_stdout_write_is_never_retried_or_mistaken_for_success(self):
        class Stdout:
            def fileno(self):
                return 1

        receipt, _ = reviewer.review(encode(fixture()))
        sink = SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=3, st_ino=5)
        with (
            patch.object(reviewer.sys, "stdout", Stdout()),
            patch.object(reviewer.os, "fstat", return_value=sink),
            patch.object(reviewer.os, "get_blocking", return_value=True),
            patch.object(reviewer.os, "set_blocking"),
            patch.object(reviewer.select, "select", return_value=([], [1], [])),
            patch.object(reviewer.os, "write", return_value=5) as send,
        ):
            self.assertFalse(reviewer._emit_receipt(receipt))
        send.assert_called_once()

    def test_256_synthetic_mixed_narrow_and_widen_combinations(self):
        # Orthogonal narrowing first; then possible authorization expansion.
        # All accepted packets are still REVIEW_ONLY, never executable.
        for bits in range(256):
            packet = fixture()
            after = packet["after"]
            if bits & 1:
                after["assets"] = ["lab-a.example"]
            if bits & 2:
                after["capabilities"] = ["tls_baseline"]
            if bits & 4:
                after["max_risk"] = 2
            if bits & 8:
                after["valid_until"] = "2026-10-14T10:00:00Z"
            if bits & 16:
                after["assets"].append("lab-c.example")
            if bits & 32:
                after["capabilities"].append("new_tool")
            if bits & 64:
                after["max_risk"] = 4
            if bits & 128:
                after["valid_from"] = "2026-10-13T00:00:00Z"
            receipt, code = reviewer.review(encode(packet))
            with self.subTest(bits=bits):
                self.assert_denied_authority(receipt, code)
                if bits & 240:
                    self.assertEqual((receipt["status"], code), ("HOLD", 2))
                else:
                    self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
    def test_regular_file_stdin_midfile_offset_never_mints_review(self):
        synthetic = encode(fixture())
        with tempfile.TemporaryFile() as stream:
            stream.write(b"PREFIX" + synthetic)
            stream.flush()
            stream.seek(6)
            child = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), "--stdin-json"],
                stdin=stream, capture_output=True, check=False, timeout=8,
            )
        self.assertEqual(child.returncode, 2)
        receipt = json.loads(child.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "invalid_input")
        self.assert_denied_authority(receipt, child.returncode)
        self.assertFalse(child.stderr)

    def test_regular_file_declared_size_must_equal_received_bytes(self):
        class Stdin:
            def fileno(self):
                return 0
        previous = SimpleNamespace(
            st_mode=stat.S_IFREG, st_dev=9, st_ino=11,
            st_size=3, st_mtime_ns=123, st_ctime_ns=456,
        )
        with (
            patch.object(reviewer.sys, "stdin", Stdin()),
            patch.object(reviewer.os, "fstat", side_effect=[previous, previous]),
            patch.object(reviewer.os, "lseek", return_value=0),
            patch.object(reviewer.os, "get_blocking", return_value=False),
            patch.object(reviewer.select, "select", return_value=([0], [], [])),
            patch.object(reviewer.os, "read", side_effect=[b"{}", b""]),
        ):
            self.assertEqual(reviewer._bounded_stdin(), b"")

    def test_regular_file_size_zero_refused_without_any_read(self):
        class Stdin:
            def fileno(self):
                return 0
        virtual = SimpleNamespace(st_mode=stat.S_IFREG, st_size=0)
        with (
            patch.object(reviewer.sys, "stdin", Stdin()),
            patch.object(reviewer.os, "fstat", return_value=virtual),
            patch.object(reviewer.os, "read") as reader,
        ):
            self.assertEqual(reviewer._bounded_stdin(), b"")
        reader.assert_not_called()

    def test_2048_real_grant_runtime_permission_differential_matrix(self):
        # Test only: evaluate actual source-model predicates on synthetic grants
        # across a finite request lattice. No issuance, storage, executor or I/O.
        from datetime import datetime, timezone
        from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition

        candidates = ("lab-a.example", "lab-b.example", "lab-c.example", "unknown.example")
        capabilities = ("http_headers", "tls_baseline", "new_tool")
        moments = (
            datetime(2026, 10, 14, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 14, 6, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 14, 23, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 15, 6, 0, tzinfo=timezone.utc),
        )

        def as_grant(d):
            return AuthorizationGrant(
                grant_id=d["grant_id"], client_id=d["client_id"],
                engagement_id=d["engagement_id"], approved_by=d["approved_by"],
                reference=d["reference"],
                scope=ScopeDefinition(
                    assets=tuple(d["assets"]),
                    excluded_assets=tuple(d["excluded_assets"]),
                    allowed_capabilities=tuple(d["capabilities"]),
                    max_risk=RiskLevel(d["max_risk"]),
                ),
                valid_from=datetime.fromisoformat(
                    d["valid_from"].replace("Z", "+00:00")
                ),
                valid_until=datetime.fromisoformat(
                    d["valid_until"].replace("Z", "+00:00")
                ),
                recurring_retest_allowed=d["recurring_retest_allowed"],
            )

        def permits(grant, asset, capability, risk, moment):
            return (
                grant.is_current(moment)
                and grant.scope.allows_asset(asset)
                and grant.scope.allows_capability(capability)
                and int(grant.scope.max_risk) >= risk
            )

        # Four real-model baseline shapes: explicit/unrestricted original
        # capabilities crossed with populated/revoked original assets.
        # Every combination compares *actual* ScopeDefinition allowances.
        for baseline_flags in range(4):
            for bits in range(512):
                item = fixture()
                if baseline_flags & 1:
                    item["before"]["capabilities"] = []
                if baseline_flags & 2:
                    item["before"]["assets"] = []
                    item["after"]["assets"] = []
                updated = item["after"]
                if bits & 1:
                    updated["assets"] = []
                if bits & 2:
                    updated["excluded_assets"].append("lab-a.example")
                if bits & 4:
                    updated["capabilities"] = ["tls_baseline"]
                if bits & 8:
                    updated["max_risk"] = 1
                if bits & 16:
                    updated["valid_from"] = "2026-10-14T06:00:00Z"
                if bits & 32:
                    updated["valid_until"] = "2026-10-14T18:00:00Z"
                if bits & 64:
                    updated["assets"].append("lab-c.example")
                if bits & 128:
                    updated["excluded_assets"] = [
                        v for v in updated["excluded_assets"] if v != "lab-b.example"
                    ]
                if bits & 256:
                    updated["capabilities"].append("new_tool")

                baseline = as_grant(item["before"])
                amended = as_grant(updated)
                receipt, code = reviewer.review(encode(item))
                with self.subTest(baseline=baseline_flags, bits=bits):
                    self.assert_denied_authority(receipt, code)
                    # A newly added tool is a widening ONLY when the source
                    # grant had an explicit capability list. If the source
                    # was unrestricted, adding a named allowed tool to an
                    # explicit after-list remains strictly narrower.
                    widened = bool(
                        (bits & (64 | 128))
                        or ((bits & 256) and not (baseline_flags & 1))
                    )
                    if widened:
                        self.assertEqual((receipt["status"], code), ("HOLD", 2))
                    else:
                        self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
                        for asset in candidates:
                            for capability in capabilities:
                                for risk in (0, 1, 2, 3, 4):
                                    for moment in moments:
                                        if permits(amended, asset, capability, risk, moment):
                                            self.assertTrue(
                                                permits(baseline, asset, capability, risk, moment),
                                                msg="offline review admitted a new real-model permission",
                                            )

    def test_full_asset_revocation_is_review_only_and_has_no_real_model_targets(self):
        from lightup.engagements import RiskLevel, ScopeDefinition

        proposal = fixture()
        proposal["after"]["assets"] = []
        receipt, code = reviewer.review(encode(proposal))
        self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(receipt, code)
        self.assertEqual(receipt["widening_dimensions"], [])

        revoked = ScopeDefinition(
            assets=tuple(proposal["after"]["assets"]),
            excluded_assets=tuple(proposal["after"]["excluded_assets"]),
            allowed_capabilities=tuple(proposal["after"]["capabilities"]),
            max_risk=RiskLevel(proposal["after"]["max_risk"]),
        )
        for asset in ("lab-a.example", "lab-b.example", "lab-c.example",
                      "other.example", ""):
            self.assertFalse(revoked.allows_asset(asset))
        self.assertFalse(receipt["authorized"])
        self.assertFalse(receipt["dispatch_enabled"])

    def test_full_asset_revocation_does_not_launder_a_widened_other_dimension(self):
        unsafe_updates = (
            ("capabilities", ["tls_baseline", "http_headers", "new_tool"], "capabilities"),
            ("max_risk", 4, "risk"),
            ("valid_until", "2026-10-16T00:00:00Z", "window"),
            ("recurring_retest_allowed", True, "recurring_retest"),
            ("approved_by", "different-operator", "identity"),
        )
        for field, widened, dimension in unsafe_updates:
            with self.subTest(field=field):
                proposal = fixture()
                proposal["after"]["assets"] = []
                proposal["after"][field] = widened
                receipt, code = reviewer.review(encode(proposal))
                self.assertEqual((receipt["status"], code), ("HOLD", 2))
                self.assertIn(dimension, receipt["widening_dimensions"])
                self.assert_denied_authority(receipt, code)

    def test_empty_new_capabilities_remains_unrestricted_and_is_refused(self):
        proposal = fixture()
        proposal["after"]["assets"] = []
        proposal["after"]["capabilities"] = []
        receipt, code = reviewer.review(encode(proposal))
        self.assertEqual((receipt["status"], code), ("HOLD", 2))
        self.assert_denied_authority(receipt, code)

    def test_before_unrestricted_capabilities_may_be_strictly_narrowed(self):
        from lightup.engagements import RiskLevel, ScopeDefinition

        grant = fixture()
        grant["before"]["capabilities"] = []
        grant["after"]["capabilities"] = ["tls_baseline"]
        receipt, code = reviewer.review(encode(grant))
        self.assertEqual((receipt["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(receipt, code)
        before = ScopeDefinition(
            assets=("lab-a.example",), max_risk=RiskLevel.STANDARD,
            allowed_capabilities=(),
        )
        after = ScopeDefinition(
            assets=("lab-a.example",), max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("tls_baseline",),
        )
        for name in ("tls_baseline", "http_headers", "unknown_tool", ""):
            self.assertTrue(before.allows_capability(name))
            if after.allows_capability(name):
                self.assertTrue(before.allows_capability(name))
        self.assertFalse(after.allows_capability("unknown_tool"))

    def test_no_caps_after_stays_hold_even_if_before_was_unrestricted(self):
        packet = fixture()
        packet["before"]["capabilities"] = []
        packet["after"]["capabilities"] = []
        output, code = reviewer.review(encode(packet))
        self.assertEqual((output["status"], code), ("HOLD", 2))
        self.assert_denied_authority(output, code)

    def test_unrestricted_before_constraining_caps_cannot_mask_other_widenings(self):
        # Six independent expansion dimensions: narrowed tool list is NOT
        # consent for wider assets, risk, time, exclusions or retest rights.
        flags = (
            ("assets", ["lab-a.example", "lab-b.example", "lab-c.example"], "assets"),
            ("max_risk", 4, "risk"),
            ("excluded_assets", [], "exclusions"),
            ("valid_until", "2026-10-16T00:00:00Z", "window"),
            ("approved_by", "unapproved-other", "identity"),
            ("recurring_retest_allowed", True, "recurring_retest"),
        )
        for mask in range(64):
            packet = fixture()
            packet["before"]["capabilities"] = []
            packet["after"]["capabilities"] = ["tls_baseline"]
            expected = set()
            for bit, (field, replacement, reason) in enumerate(flags):
                if mask & (1 << bit):
                    packet["after"][field] = replacement
                    expected.add(reason)
            outcome, code = reviewer.review(encode(packet))
            with self.subTest(mask=mask):
                self.assert_denied_authority(outcome, code)
                if expected:
                    self.assertEqual((outcome["status"], code), ("HOLD", 2))
                    self.assertEqual(outcome["widening_dimensions"], sorted(expected))
                else:
                    self.assertEqual((outcome["status"], code), ("REVIEW_ONLY", 3))

    def test_unrestricted_before_with_revoked_targets_still_never_authorizes(self):
        packet = fixture()
        packet["before"]["capabilities"] = []
        packet["after"]["capabilities"] = ["tls_baseline"]
        packet["after"]["assets"] = []
        packet["after"]["max_risk"] = 1
        output, code = reviewer.review(encode(packet))
        self.assertEqual((output["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(output, code)

    def test_already_revoked_assets_remain_valid_non_authorizing_review(self):
        from lightup.engagements import RiskLevel, ScopeDefinition

        item = fixture()
        item["before"]["assets"] = []
        item["after"]["assets"] = []
        out, code = reviewer.review(encode(item))
        self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
        self.assert_denied_authority(out, code)
        actual = ScopeDefinition(
            assets=(), max_risk=RiskLevel.STANDARD,
            allowed_capabilities=("http_headers", "tls_baseline"),
        )
        for asset in ("lab-a.example", "lab-b.example", "new.example", ""):
            self.assertFalse(actual.allows_asset(asset))

    def test_assets_cannot_return_after_a_full_revocation(self):
        for targets in (
            ["lab-a.example"], ["lab-b.example"], ["new.example"],
            ["lab-a.example", "lab-b.example"],
        ):
            item = fixture()
            item["before"]["assets"] = []
            item["after"]["assets"] = targets
            out, code = reviewer.review(encode(item))
            with self.subTest(targets=targets):
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertEqual(out["widening_dimensions"], ["assets"])
                self.assert_denied_authority(out, code)

    def test_sequential_complete_revocation_stays_monotone(self):
        # Two independent snapshots, no persisted grant issuance. The second
        # review is from the *already-revoked* state, not the original grant.
        first = fixture()
        first["after"]["assets"] = []
        first["after"]["max_risk"] = 1
        second = fixture()
        second["before"] = copy.deepcopy(first["after"])
        second["after"] = copy.deepcopy(second["before"])
        second["after"]["capabilities"] = ["tls_baseline"]
        second["after"]["recurring_retest_allowed"] = False
        merged = fixture()
        merged["after"] = copy.deepcopy(second["after"])
        for pair in (first, second, merged):
            out, code = reviewer.review(encode(pair))
            self.assertEqual((out["status"], code), ("REVIEW_ONLY", 3))
            self.assert_denied_authority(out, code)
        second["after"]["assets"] = ["lab-a.example"]
        out, code = reviewer.review(encode(second))
        self.assertEqual((out["status"], code), ("HOLD", 2))
        self.assertIn("assets", out["widening_dimensions"])

    def test_empty_before_assets_cannot_hide_other_expansion(self):
        fields = (
            ("approved_by", "operator-other", "identity"),
            ("valid_from", "2026-10-13T00:00:00Z", "window"),
            ("max_risk", 4, "risk"),
            ("recurring_retest_allowed", True, "recurring_retest"),
            ("excluded_assets", [], "exclusions"),
            ("capabilities", ["http_headers", "tls_baseline", "new_tool"], "capabilities"),
        )
        for name, replacement, expected in fields:
            item = fixture()
            item["before"]["assets"] = []
            item["after"]["assets"] = []
            item["after"][name] = replacement
            with self.subTest(name=name):
                out, code = reviewer.review(encode(item))
                self.assertEqual((out["status"], code), ("HOLD", 2))
                self.assertIn(expected, out["widening_dimensions"])
                self.assert_denied_authority(out, code)

    def test_canonical_utc_fields_deny_every_unicode_decimal_confusable(self):
        # A Python regex \\d accepts Unicode Nd digits. The reviewer must
        # fail at the *format* gate, without depending on datetime parser
        # leniency or future normalization in standard-library upgrades.
        canonical = "2026-10-14T12:34:56Z"
        positions = [i for i, char in enumerate(canonical) if char.isdecimal()]
        for replacement in ("٢", "２", "𝟚"):
            for pos in positions:
                variant = canonical[:pos] + replacement + canonical[pos + 1:]
                with self.subTest(glyph=replacement, position=pos):
                    with self.assertRaises(reviewer.Rejected) as ctx:
                        reviewer._instant(variant)
                    self.assertEqual(str(ctx.exception), "instant_format")
                    item = fixture()
                    item["after"]["valid_until"] = variant
                    receipt, code = reviewer.review(encode(item))
                    self.assertEqual((receipt["status"], code), ("HOLD", 2))
                    self.assertEqual(receipt["reason"], "invalid_input")
                    self.assert_denied_authority(receipt, code)

    def test_utc_ascii_digits_are_still_accepted_at_both_boundaries(self):
        for ts in (
            "0001-01-01T00:00:00Z", "2024-02-29T23:59:59Z",
            "2026-10-14T00:00:00Z", "9999-12-31T23:59:59Z",
        ):
            with self.subTest(timestamp=ts):
                self.assertEqual(reviewer._instant(ts).tzinfo.utcoffset(None).total_seconds(), 0)
        for malformed in (
            "2026-10-14T12:34:60Z", "2026-02-29T12:34:56Z",
            "2026-10-14T24:00:00Z", "2026-10-14t12:34:56z",
        ):
            with self.subTest(timestamp=malformed):
                with self.assertRaises(reviewer.Rejected):
                    reviewer._instant(malformed)

    def test_cli_rejects_no_flag(self):
        result = subprocess.run(
            [sys.executable, "-B", str(SCRIPT)],
            input=b"", capture_output=True, check=False, timeout=8,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
