"""Synthetic, offline scope metadata review tests. No targets or grants."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import tempfile
import textwrap
import pathlib
import random
import socket
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_asset_unicode_20261015_offline.py"
SPEC = importlib.util.spec_from_file_location("asset_metadata_review_1437", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def synthetic_claim():
    return {
        "assets": ["app.example.test", "api.example.test"],
        "excluded_assets": ["retired.example.test"],
        "allowed_capabilities": ["web-baseline", "tls.v1"],
    }


def receipt(value):
    return mod.review_bytes(json.dumps(value, ensure_ascii=False).encode("utf-8"))


class ScopeAssetUnicodeReviewTests(unittest.TestCase):
    def assert_hold(self, got):
        self.assertEqual(got, {"status": "HOLD", **mod.FALSE_FLAGS})
        self.assertTrue(all(got[k] is False for k in mod.FALSE_FLAGS))

    def assert_review(self, got):
        self.assertEqual(got["status"], "REVIEW_ONLY")
        self.assertTrue(all(got[k] is False for k in mod.FALSE_FLAGS))
        self.assertEqual(set(got) - set(mod.FALSE_FLAGS),
                         {"status", "asset_count", "excluded_count", "capability_count"})
        self.assertEqual((got["asset_count"], got["excluded_count"], got["capability_count"]),
                         (2, 1, 2))

    def test_valid_synthetic_claim_is_review_only_and_never_approved(self):
        self.assert_review(receipt(synthetic_claim()))

    def test_unicode_and_alias_hazards_are_atomic_hold(self):
        suspects = [
            "аpp.example.test", "ａｐｐ.example.test", "app.ｅxample.test",
            "app\u200b.example.test", "app\u202e.example.test",
            "app\n.example.test", "app\t.example.test",
            "APP.EXAMPLE.TEST", " app.example.test", "app.example.test ",
            "xn--e1afmkfd.example.test", "api..example.test",
            "-app.example.test", "app-.example.test", "app.example.test.",
            "https://app.example.test", "user@app.example.test", "app.example.test:443",
            "app.example.test/path", "*.example.test", "app.example.test?x=1",
            "app.example.test#frag", "[::1]", "", ".", "a" * 64 + ".test",
        ]
        for value in suspects:
            with self.subTest(value=repr(value)):
                sample = synthetic_claim()
                sample["assets"][0] = value
                self.assert_hold(receipt(sample))
                sample = synthetic_claim()
                sample["excluded_assets"][0] = value
                self.assert_hold(receipt(sample))

    def test_duplicate_collision_and_explicit_capabilities(self):
        modifications = [
            ("assets", ["api.example.test", "api.example.test"]),
            ("excluded_assets", ["app.example.test"]),
            ("excluded_assets", ["retired.example.test"] * 2),
            ("allowed_capabilities", []),
            ("allowed_capabilities", ["web-baseline"] * 2),
            ("allowed_capabilities", ["WEB-BASELINE"]),
            ("allowed_capabilities", [""]),
            ("allowed_capabilities", ["web.*"]),
            ("allowed_capabilities", ["web\u200d-baseline"]),
            ("assets", []),
            ("assets", ["a.test"] * 33),
        ]
        for field, value in modifications:
            with self.subTest(field=field, value=value):
                sample = synthetic_claim()
                sample[field] = value
                self.assert_hold(receipt(sample))

    def test_json_escaped_aliases_are_hold_even_when_decoded_identity_is_canonical(self):
        data = json.dumps(synthetic_claim(), separators=(",", ":")).encode()
        alternate_wires = (
            data.replace(b"app.example.test", b"\\u0061pp.example.test"),
            data.replace(b"api.example.test", b"\\u0061pi.example.test"),
            data.replace(b"tls.v1", b"tls\\u002ev1"),
            data.replace(b"web-baseline", b"web\\u002dbaseline"),
            data.replace(b"example.test", b"example\\u002etest"),
            data.replace(b"app.example.test", b"app\\/example.test"),
        )
        for raw in alternate_wires:
            with self.subTest(wire=raw[:96]):
                self.assert_hold(mod.review_bytes(raw))
                cli = subprocess.run(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    input=raw, capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(cli.returncode, 2)
                self.assertEqual(cli.stderr, b"")
                self.assert_hold(json.loads(cli.stdout))
                self.assertNotIn(b"app.example.test", cli.stdout)
        self.assertEqual(mod.review_bytes(data)["status"], "REVIEW_ONLY")

    def test_json_duplicate_escaped_keys_nonfinite_and_extras(self):
        bad_bytes = [
            b'{"assets":[],"assets":[],"excluded_assets":[],"allowed_capabilities":[]}',
            b'{"assets":[],"as\\u0073ets":[],"excluded_assets":[],"allowed_capabilities":[]}',
            b'{"assets":[],"excluded_assets":[],"allowed_capabilities":[],"approved":true}',
            b'{"assets":NaN,"excluded_assets":[],"allowed_capabilities":[]}',
            b'{"assets":Infinity,"excluded_assets":[],"allowed_capabilities":[]}',
            b'\xef\xbb\xbf{}', b'{} trailing', b'\xff', b'', b' ' * 8193,
            b'[' * 250 + b']' * 250,
            b'{"assets":["\\ud800"],"excluded_assets":[],"allowed_capabilities":["x"]}',
        ]
        for bad in bad_bytes:
            with self.subTest(case=bad[:40]):
                self.assert_hold(mod.review_bytes(bad))

    def test_numeric_ipv4_aliases_fail_closed(self):
        for text in ("127.1", "2130706433", "0177.0.0.1", "127.000.0.1",
                     "1.2.3.999", "1.2.3", "0", "000", "1.2.3.4.5"):
            with self.subTest(text=text):
                sample = synthetic_claim()
                sample["assets"][0] = text
                self.assert_hold(receipt(sample))
        sample = synthetic_claim()
        sample["assets"][0] = "127.0.0.1"
        self.assertEqual(receipt(sample)["status"], "REVIEW_ONLY")

    def test_exact_types_do_not_accept_polymorphic_or_bools(self):
        class ForgedStr(str):
            pass
        class ForgedList(list):
            pass
        class ForgedDict(dict):
            pass
        sample = synthetic_claim()
        sample["assets"][0] = ForgedStr("app.example.test")
        with self.assertRaises(mod.ReviewInputError):
            mod.inspect_synthetic_claim(sample)
        sample = synthetic_claim()
        sample["assets"] = ForgedList(sample["assets"])
        with self.assertRaises(mod.ReviewInputError):
            mod.inspect_synthetic_claim(sample)
        sample = ForgedDict(synthetic_claim())
        with self.assertRaises(mod.ReviewInputError):
            mod.inspect_synthetic_claim(sample)
        sample = synthetic_claim()
        sample["allowed_capabilities"] = [True]
        self.assert_hold(receipt(sample))

    def test_order_invariance_and_no_implicit_wildcard(self):
        rng = random.Random(1437)
        base = synthetic_claim()
        expected = receipt(base)
        for _ in range(100):
            other = {key: rng.sample(value, len(value)) for key, value in base.items()}
            self.assertEqual(receipt(other), expected)
        for field in base:
            modified = synthetic_claim()
            modified[field].append("hidden\u200b.example.test")
            self.assert_hold(receipt(modified))

    def test_fragmented_local_pipe_and_unclosed_stream_are_fail_closed(self):
        data = json.dumps(synthetic_claim()).encode("utf-8")
        original = subprocess.run(
            [sys.executable, str(SCRIPT), "--stdin-json"], input=data,
            capture_output=True, timeout=5, check=False)
        child = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert child.stdin is not None
        for chunk in (data[:9], data[9:35], data[35:]):
            child.stdin.write(chunk)
            child.stdin.flush()
        child.stdin.close()
        child.stdin = None
        out, err = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 3)
        self.assertEqual(out, original.stdout)
        self.assertEqual(err, b"")
        child = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert child.stdin is not None and child.stdout is not None
        child.stdin.write(b'{"assets":[')
        child.stdin.flush()
        self.assertEqual(child.wait(timeout=5), 2)
        denied = child.stdout.read()
        self.assert_hold(json.loads(denied))
        self.assertEqual(child.stderr.read(), b"")
        child.stdin.close()
        child.stdout.close()
        child.stderr.close()

    def test_real_cli_oversized_input_is_generic_hold(self):
        data = b"SENSITIVE-ASSET-EXAMPLE" * 700
        proc = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                              input=data, capture_output=True, timeout=5,
                              check=False)
        self.assertEqual(proc.returncode, 2)
        self.assert_hold(json.loads(proc.stdout))
        self.assertNotIn(b"SENSITIVE-ASSET-EXAMPLE", proc.stdout)
        self.assertEqual(proc.stderr, b"")

    def test_fifo_eagain_after_readiness_uses_deadline_and_restores_fd_mode(self):
        data = json.dumps(synthetic_claim()).encode()
        program = textwrap.dedent("""
            import importlib.util
            import json
            import os
            from unittest import mock
            import sys
            spec = importlib.util.spec_from_file_location("offline_review_1437", sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            original = os.read
            errors = [3]
            def intermittent(fd, size):
                if errors[0]:
                    errors[0] -= 1
                    raise BlockingIOError(11, "temporary EAGAIN")
                return original(fd, size)
            before = os.get_blocking(0)
            with mock.patch.object(module.os, "read", side_effect=intermittent):
                read = module._read_local_stdin()
            after = os.get_blocking(0)
            print(json.dumps({"same": read == DATA, "before": before, "after": after}))
        """).replace("DATA", repr(data))
        child = subprocess.run([sys.executable, "-c", program, str(SCRIPT)],
                               input=data, capture_output=True, timeout=5, check=False)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))
        outcome = json.loads(child.stdout)
        self.assertTrue(outcome["same"])
        self.assertEqual(outcome["before"], outcome["after"])
        self.assertEqual(child.stderr, b"")

    def test_regular_file_stdin_restores_blocking_mode_after_snapshot(self):
        data = json.dumps(synthetic_claim()).encode()
        program = textwrap.dedent("""
            import importlib.util
            import json
            import os
            import sys
            spec = importlib.util.spec_from_file_location("offline_review_1437", sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            before = os.get_blocking(0)
            read = module._read_local_stdin()
            after = os.get_blocking(0)
            print(json.dumps({"same": read == DATA, "before": before, "after": after}))
        """).replace("DATA", repr(data))
        with tempfile.TemporaryFile() as fixture:
            fixture.write(data)
            fixture.seek(0)
            child = subprocess.run([sys.executable, "-c", program, str(SCRIPT)],
                                   stdin=fixture, capture_output=True, timeout=5,
                                   check=False)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))
        outcome = json.loads(child.stdout)
        self.assertTrue(outcome["same"])
        self.assertEqual(outcome["before"], outcome["after"])
        self.assertEqual(child.stderr, b"")

    def test_forged_fd0_identity_is_denied_at_each_read_boundary(self):
        """Child-local adversarial fstat mutation: before read, midstream, EOF."""
        data = json.dumps(synthetic_claim()).encode()
        for threshold in (2, 3, 4):
            program = textwrap.dedent("""
                import importlib.util, os, sys
                from unittest import mock
                spec = importlib.util.spec_from_file_location("offline_review_1437", sys.argv[1])
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                origin = os.fstat
                initial = origin(0)
                fields = list(initial)
                fields[1] += 12345
                forged = os.stat_result(fields)
                seen = [0]
                def fake_fstat(fd):
                    if fd == 0:
                        seen[0] += 1
                        if seen[0] >= THRESHOLD:
                            return forged
                    return origin(fd)
                prior = os.get_blocking(0)
                try:
                    with mock.patch.object(module.os, "fstat", side_effect=fake_fstat):
                        module._read_local_stdin()
                except module.ReviewInputError:
                    if os.get_blocking(0) != prior:
                        raise AssertionError("stdin nonblocking flag not restored")
                    sys.exit(0)
                raise AssertionError("falsified descriptor identity was accepted")
            """).replace("THRESHOLD", str(threshold))
            with self.subTest(threshold=threshold):
                child = subprocess.run(
                    [sys.executable, "-c", program, str(SCRIPT)], input=data,
                    capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(child.returncode, 0,
                                 child.stderr.decode(errors="replace"))
                self.assertEqual(child.stdout, b"")
                self.assertEqual(child.stderr, b"")

    def test_forged_stdout_identity_refuses_to_emit_receipt(self):
        program = textwrap.dedent("""
            import importlib.util, os, sys
            from unittest import mock
            spec = importlib.util.spec_from_file_location("offline_review_1437", sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            origin = os.fstat
            fields = list(origin(1))
            fields[1] += 12345
            forged = os.stat_result(fields)
            seen = [0]
            def fake_fstat(fd):
                if fd == 1:
                    seen[0] += 1
                    if seen[0] >= 2:
                        return forged
                return origin(fd)
            with mock.patch.object(module.os, "fstat", side_effect=fake_fstat):
                accepted = module._emit_local_receipt(
                    {"status": "HOLD", **module.FALSE_FLAGS}
                )
            if accepted:
                raise AssertionError("stdout identity swap was accepted")
        """)
        child = subprocess.run(
            [sys.executable, "-c", program, str(SCRIPT)],
            input=b"", capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(child.returncode, 0,
                         child.stderr.decode(errors="replace"))
        self.assertEqual(child.stdout, b"")
        self.assertEqual(child.stderr, b"")

    def test_regular_file_snapshot_and_seeked_file_hold(self):
        data = json.dumps(synthetic_claim()).encode("utf-8")
        with tempfile.TemporaryFile(mode="w+b") as fixture:
            fixture.write(data)
            fixture.flush()
            fixture.seek(0)
            correct = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                     stdin=fixture, capture_output=True,
                                     timeout=5, check=False)
            self.assertEqual(correct.returncode, 3)
            self.assert_review(json.loads(correct.stdout))
            self.assertEqual(correct.stderr, b"")
            fixture.seek(1)
            shifted = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                     stdin=fixture, capture_output=True,
                                     timeout=5, check=False)
            self.assertEqual(shifted.returncode, 2)
            self.assert_hold(json.loads(shifted.stdout))
            self.assertEqual(shifted.stderr, b"")

    def test_reject_nonlocal_stdin_descriptor(self):
        with open(os.devnull, "rb") as invalid:
            proc = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                  stdin=invalid, capture_output=True,
                                  timeout=5, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assert_hold(json.loads(proc.stdout))
        self.assertEqual(proc.stderr, b"")

    def test_receipt_gate_refuses_caller_forged_success_or_leaky_shape(self):
        class ForgedStatus(str):
            def __eq__(self, other):
                return other in {"HOLD", "REVIEW_ONLY"}

        self.assertTrue(mod._is_deny_only_receipt({"status": "HOLD", **mod.FALSE_FLAGS}))
        self.assertTrue(mod._is_deny_only_receipt(receipt(synthetic_claim())))
        forged = [
            {"status": "APPROVED", **mod.FALSE_FLAGS},
            {"status": "PASS", **mod.FALSE_FLAGS},
            {"status": ForgedStatus("REVIEW_ONLY"), **mod.FALSE_FLAGS},
            {"status": "HOLD", **mod.FALSE_FLAGS, "asset_count": 0},
            {"status": "REVIEW_ONLY", **mod.FALSE_FLAGS},
            {**receipt(synthetic_claim()), "asset": "PRIVATE-ASSET"},
            {**receipt(synthetic_claim()), "authorization_verified": True},
            {**receipt(synthetic_claim()), "release_approved": 0},
            {**receipt(synthetic_claim()), "asset_count": True},
            {**receipt(synthetic_claim()), "capability_count": -1},
            {**receipt(synthetic_claim()), "excluded_count": 33},
            {**receipt(synthetic_claim()), "status": "HOLD"},
            ["HOLD"],
        ]
        for item in forged:
            with self.subTest(receipt=item):
                self.assertFalse(mod._is_deny_only_receipt(item))

    def test_static_offline_import_and_effect_boundary_with_negative_controls(self):
        """Fixture gate: no socket/http/process launch/target data facilities."""
        allowed = {
            "__future__", "json", "ipaddress", "os", "re", "select",
            "stat", "sys", "time", "typing",
        }
        deny_os_calls = {
            "open", "system", "popen", "fork", "execv", "execve",
            "spawnv", "spawnve", "listdir", "scandir", "walk",
        }
        deny_dynamic_calls = {"__import__", "eval", "exec", "compile", "open"}

        def offenses(source):
            findings = []
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.partition(".")[0] not in allowed:
                            findings.append(("import", alias.name))
                if isinstance(node, ast.ImportFrom):
                    if (node.module or "").partition(".")[0] not in allowed:
                        findings.append(("import-from", node.module))
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in deny_dynamic_calls:
                        findings.append(("dynamic", node.func.id))
                    if (
                        isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "os"
                        and node.func.attr in deny_os_calls
                    ):
                        findings.append(("os-effect", node.func.attr))
            return findings

        self.assertEqual(offenses(SCRIPT.read_text(encoding="utf-8")), [])
        fake_mutants = (
            "import socket\nsocket.create_connection(('example.invalid',80))",
            "from urllib import request\nrequest.urlopen('http://example.invalid')",
            "import subprocess\nsubprocess.run(['python'])",
            "import os\nos.system('echo mutated')",
            "__import__('socket')",
            "open('secrets.txt')",
        )
        for mutated in fake_mutants:
            with self.subTest(mutant=mutated[:32]):
                self.assertNotEqual(offenses(mutated), [])

    def test_installed_source_never_imports_untrusted_reviewer(self):
        for path in (ROOT / "src" / "lightup").rglob("*.py"):
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertNotIn("review_scope_asset_unicode_20261015_offline",
                                 path.read_text(encoding="utf-8"))

    def test_local_input_output_alias_is_rejected(self):
        reader, writer = os.pipe()
        try:
            self.assertTrue(mod._same_descriptor(os.fstat(reader), os.fstat(writer)))
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_same_pipe_stdin_stdout_cannot_emit_receipt(self):
        reader, writer = os.pipe()
        try:
            child = subprocess.Popen([sys.executable, str(SCRIPT), "--stdin-json"],
                                     stdin=reader, stdout=writer,
                                     stderr=subprocess.PIPE)
            self.assertEqual(child.wait(timeout=5), 2)
            self.assertEqual(child.stderr.read(), b"")
            child.stderr.close()
            os.close(writer)
            writer = -1
            self.assertEqual(os.read(reader, 1024), b"")
        finally:
            if writer != -1:
                os.close(writer)
            os.close(reader)

    def test_input_exact_byte_ceiling_and_overrun(self):
        payload = json.dumps(synthetic_claim(), separators=(",", ":")).encode()
        self.assertLess(len(payload), mod.MAX_INPUT_BYTES)
        exact = payload + b" " * (mod.MAX_INPUT_BYTES - len(payload))
        for data, code in ((exact, 3), (exact + b" ", 2)):
            with self.subTest(length=len(data)):
                proc = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                      input=data, capture_output=True,
                                      timeout=5, check=False)
                self.assertEqual(proc.returncode, code)
                self.assertEqual(proc.stderr, b"")
                verdict = json.loads(proc.stdout)
                self.assertEqual(verdict["status"],
                                 "REVIEW_ONLY" if code == 3 else "HOLD")
                self.assertTrue(all(verdict[key] is False for key in mod.FALSE_FLAGS))

    def test_output_is_local_pipe_only_not_regular_file_or_socket(self):
        data = json.dumps(synthetic_claim()).encode("utf-8")
        with tempfile.TemporaryFile(mode="w+b") as sink:
            result = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                    input=data, stdout=sink, stderr=subprocess.PIPE,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"")
            sink.seek(0)
            self.assertEqual(sink.read(), b"")
        with open(os.devnull, "wb") as sink:
            result = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                    input=data, stdout=sink, stderr=subprocess.PIPE,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"")
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            result = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                    input=data, stdout=right, stderr=subprocess.PIPE,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"")
            right.shutdown(socket.SHUT_WR)
            left.settimeout(2)
            self.assertEqual(left.recv(1024), b"")
        finally:
            left.close()
            right.close()

    def test_full_local_output_pipe_never_blocks_or_emits_partial_result(self):
        rd, wr = os.pipe()
        try:
            os.set_blocking(wr, False)
            while True:
                try:
                    os.write(wr, b"z" * 512)
                except BlockingIOError:
                    break
            os.set_blocking(wr, True)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                input=json.dumps(synthetic_claim()).encode(),
                stdout=wr, stderr=subprocess.PIPE, timeout=5, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"")
            os.set_blocking(rd, False)
            remaining = bytearray()
            while True:
                try:
                    chunk = os.read(rd, 8192)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                remaining.extend(chunk)
            self.assertTrue(remaining)
            self.assertEqual(set(remaining), {ord("z")})
        finally:
            os.close(wr)
            os.close(rd)

    def test_real_cli_never_success_or_leaks_input(self):
        payloads = [
            (json.dumps(synthetic_claim()).encode(), 3, "REVIEW_ONLY"),
            (b'{"client":"PRIVATE-ID","approved":true}', 2, "HOLD"),
            (json.dumps({**synthetic_claim(), "assets": ["SECRET-CUSTOMER"]}).encode(), 2, "HOLD"),
        ]
        for data, exit_code, status in payloads:
            proc = subprocess.run([sys.executable, str(SCRIPT), "--stdin-json"],
                                  input=data, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=5, check=False)
            self.assertEqual(proc.returncode, exit_code)
            self.assertEqual(proc.stderr, b"")
            self.assertEqual(len(proc.stdout.splitlines()), 1)
            value = json.loads(proc.stdout)
            self.assertEqual(value["status"], status)
            self.assertTrue(all(value[key] is False for key in mod.FALSE_FLAGS))
            self.assertNotIn(b"PRIVATE-ID", proc.stdout)
            self.assertNotIn(b"SECRET-CUSTOMER", proc.stdout)
        proc = subprocess.run([sys.executable, str(SCRIPT), "--approved"],
                              input=b"SECRET-CUSTOMER", capture_output=True,
                              timeout=5, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assert_hold(json.loads(proc.stdout))
        self.assertEqual(proc.stderr, b"")


if __name__ == "__main__":
    unittest.main()
