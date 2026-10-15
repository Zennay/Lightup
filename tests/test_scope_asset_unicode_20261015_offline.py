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

    def test_hex_numeric_ipv4_aliases_are_atomic_hold(self):
        # inet_aton is only an in-process numeric parser; no lookup/network call.
        aliases = ("0x7f.0.0.1", "0x7f000001", "0x7f.1",
                   "0x7f.0.1", "0x7f.00.01", "0x7f000001")
        canonical = socket.inet_aton("127.0.0.1")
        for value in aliases:
            with self.subTest(value=value):
                self.assertEqual(socket.inet_aton(value), canonical)
                sample = synthetic_claim()
                sample["assets"][0] = value
                self.assert_hold(receipt(sample))
                sample = synthetic_claim()
                sample["excluded_assets"] = [value]
                self.assert_hold(receipt(sample))
                raw = json.dumps(sample, separators=(",", ":")).encode()
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    input=raw, capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(proc.returncode, 2)
                self.assert_hold(json.loads(proc.stdout))
                self.assertEqual(proc.stderr, b"")
        valid = synthetic_claim()
        valid["assets"] = ["app.0x7f.example.test"]
        self.assertEqual(receipt(valid)["status"], "REVIEW_ONLY")
        self.assertEqual(receipt(synthetic_claim())["status"], "REVIEW_ONLY")

    def test_seeded_numeric_hex_alias_variations_never_gain_review(self):
        rng = random.Random(1437_21)
        for _ in range(200):
            count = rng.randint(1, 4)
            parts = [str(rng.randrange(0, 128)) for _ in range(count)]
            parts[rng.randrange(count)] = "0x" + format(rng.randrange(0, 256), "x")
            alias = ".".join(parts)
            sample = synthetic_claim()
            sample["assets"][0] = alias
            with self.subTest(alias=alias):
                self.assert_hold(receipt(sample))

    def test_legacy_ipv4_parser_differential_is_conservative(self):
        """Numeric parsing only, with no hostname resolution or network traffic."""
        from ipaddress import IPv4Address

        rng = random.Random(1437_22)
        numeric_values = (0, 1, 7, 8, 10, 15, 16, 64, 127, 255, 256,
                          511, 1024, 65535, 0x7f000001, 0xffffffff)
        encoders = (
            str, lambda n: "0" + format(n, "o"),
            lambda n: "0x" + format(n, "x"),
        )
        parsed = 0
        rejected_aliases = 0
        for _ in range(1200):
            parts = [
                rng.choice(encoders)(rng.choice(numeric_values))
                for _ in range(rng.randint(1, 4))
            ]
            candidate = ".".join(parts)
            try:
                legacy_value = socket.inet_aton(candidate)
            except OSError:
                continue
            parsed += 1
            try:
                canonical = str(IPv4Address(candidate)) == candidate
            except ValueError:
                canonical = False
            expected = "REVIEW_ONLY" if canonical else "HOLD"
            payload = synthetic_claim()
            payload["assets"] = [candidate]
            outcome = receipt(payload)
            with self.subTest(candidate=candidate):
                self.assertEqual(outcome["status"], expected)
                self.assertTrue(all(outcome[k] is False for k in mod.FALSE_FLAGS))
                if canonical:
                    self.assertEqual(legacy_value, socket.inet_aton(candidate))
                else:
                    rejected_aliases += 1
        self.assertGreater(parsed, 100)
        self.assertGreater(rejected_aliases, 80)

    def test_exact_dns_label_name_and_capability_ceiling_boundaries(self):
        longest_name = ".".join(["a" * 63] * 3 + ["b" * 61])
        over_name = ".".join(["a" * 63] * 3 + ["b" * 62])
        self.assertEqual((len(longest_name), len(over_name)), (253, 254))
        for name in ("a" * 63 + ".test", "a--b.example.test", longest_name):
            with self.subTest(valid=name[:24]):
                sample = synthetic_claim()
                sample["assets"] = [name]
                self.assertEqual(receipt(sample)["status"], "REVIEW_ONLY")
        for name in ("a" * 64 + ".test", over_name, "a" * 63 + "..test",
                     "xn--" + "a" * 59 + ".test", "a." + "b" * 64):
            with self.subTest(invalid=name[:24]):
                sample = synthetic_claim()
                sample["assets"] = [name]
                self.assert_hold(receipt(sample))
        for cap in ("x" * 96, "web-baseline_v1.2", "a", "a1_b2-c3.d4"):
            with self.subTest(valid_cap=cap[:24]):
                sample = synthetic_claim()
                sample["allowed_capabilities"] = [cap]
                self.assertEqual(receipt(sample)["status"], "REVIEW_ONLY")
        for cap in ("x" * 97, "web..baseline", "web_.baseline", "web/scan",
                    "_web", "web-", "web__v1"):
            with self.subTest(invalid_cap=cap[:24]):
                sample = synthetic_claim()
                sample["allowed_capabilities"] = [cap]
                self.assert_hold(receipt(sample))

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
        sample[ForgedStr("assets")] = sample.pop("assets")
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

    def test_same_size_regular_file_rewrite_fails_second_byte_readback(self):
        """Synthetic in-process mutation; falsified stable stats must not suffice."""
        good = json.dumps(synthetic_claim(), separators=(",", ":")).encode()
        other = good.replace(b"app.example.test", b"bad.example.test")
        self.assertEqual(len(good), len(other))
        program = textwrap.dedent("""
            import importlib.util, os, sys
            from unittest import mock
            spec = importlib.util.spec_from_file_location("review_offline", sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            original_read = os.read
            real_fstat = os.fstat
            original_stat = real_fstat(0)
            original_block = os.get_blocking(0)
            changed = [False]
            def rewrite_after_first_read(fd, limit):
                value = original_read(fd, limit)
                if value and not changed[0]:
                    changed[0] = True
                    os.pwrite(fd, OTHER, 0)
                return value
            def stable_stat(fd):
                actual = real_fstat(fd)
                return original_stat if actual.st_ino == original_stat.st_ino else actual
            try:
                with mock.patch.object(module.os, "read", side_effect=rewrite_after_first_read):
                    with mock.patch.object(module.os, "fstat", side_effect=stable_stat):
                        module._read_local_stdin()
            except module.ReviewInputError:
                if not changed[0] or os.get_blocking(0) != original_block:
                    raise AssertionError("readback refusal or cleanup incorrect")
                sys.exit(0)
            raise AssertionError("same-size rewritten bytes accepted")
        """).replace("OTHER", repr(other))
        with tempfile.TemporaryFile(mode="w+b") as fd:
            fd.write(good)
            fd.flush()
            fd.seek(0)
            result = subprocess.run(
                [sys.executable, "-c", program, str(SCRIPT)],
                stdin=fd, capture_output=True, timeout=5, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")

    def test_real_regular_file_mutation_during_read_denies_snapshot(self):
        """Modify ONLY a disposable synthetic local regular file while reading."""
        data = json.dumps(synthetic_claim()).encode("utf-8")
        program = textwrap.dedent("""
            import importlib.util
            import os
            import sys
            from unittest import mock
            spec = importlib.util.spec_from_file_location("offline_review_1437", sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            original = os.read
            mutated = [False]
            def mutate(fd, count):
                result = original(fd, count)
                if result and not mutated[0]:
                    mutated[0] = True
                    os.ftruncate(fd, 0)
                return result
            before = os.get_blocking(0)
            try:
                with mock.patch.object(module.os, "read", side_effect=mutate):
                    module._read_local_stdin()
            except module.ReviewInputError:
                if not mutated[0] or os.get_blocking(0) != before:
                    raise AssertionError("snapshot rejection did not restore input")
                sys.exit(0)
            raise AssertionError("modified synthetic input file was accepted")
        """)
        with tempfile.TemporaryFile() as source:
            source.write(data)
            source.seek(0)
            child = subprocess.run([sys.executable, "-c", program, str(SCRIPT)],
                                   stdin=source, capture_output=True, timeout=5,
                                   check=False)
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
            {**mod.FALSE_FLAGS, "status": "HOLD", "asset_count": 1},
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
        class ForgedKey(str):
            pass

        forged_key_receipt = {"status": "HOLD", **mod.FALSE_FLAGS}
        forged_key_receipt[ForgedKey("status")] = forged_key_receipt.pop("status")
        self.assertFalse(mod._is_deny_only_receipt(forged_key_receipt))

    def test_static_offline_import_and_effect_boundary_with_negative_controls(self):
        """Fixture gate: no socket/http/process launch/target data facilities."""
        allowed_direct_imports = {"json", "os", "re", "select", "stat", "sys", "time"}
        allowed_from_imports = {
            "__future__": {"annotations"},
            "ipaddress": {"IPv4Address"},
            "typing": {"Any"},
        }
        allowed_os_attrs = {
            "stat_result", "SEEK_CUR", "SEEK_SET", "fstat", "dup", "lseek", "read", "close",
            "get_blocking", "set_blocking", "isatty", "write",
        }
        deny_dynamic_calls = {
            "__import__", "eval", "exec", "compile", "open",
            "getattr", "setattr", "delattr", "globals", "locals", "vars",
        }

        def offenses(source):
            findings = []
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name not in allowed_direct_imports or alias.asname is not None:
                            findings.append(("import", alias.name))
                if isinstance(node, ast.ImportFrom):
                    allowed_names = allowed_from_imports.get(node.module or "", set())
                    if node.level or not allowed_names or any(
                        alias.name not in allowed_names or alias.asname is not None
                        for alias in node.names
                    ):
                        findings.append(("import-from", node.module))
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr not in allowed_os_attrs
                ):
                    findings.append(("os-effect", node.attr))
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in deny_dynamic_calls
                ):
                    findings.append(("dynamic", node.func.id))
            return findings

        self.assertEqual(offenses(SCRIPT.read_text(encoding="utf-8")), [])
        fake_mutants = (
            "import socket\nsocket.create_connection(('example.invalid',80))",
            "from urllib import request\nrequest.urlopen('http://example.invalid')",
            "import subprocess\nsubprocess.run(['python'])",
            "import os\nos.system('echo mutated')",
            "import os\nos.execvp('sh', ['sh'])",
            "import os\nos.ftruncate(4, 0)",
            "import os\nos.unlink('/tmp/fake')",
            "import os\nos.environ.get('TOKEN')",
            "import os as safe\nsafe.system('echo fake')",
            "from os import system\nsystem('echo fake')",
            "from sys import modules\nmodules['os']",
            "import os.path\nos.path.exists('/tmp/fake')",
            "getattr(os, 'system')('echo fake')",
            "globals()['__builtins__']",
            "setattr(os, 'system', lambda x: None)",
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

    def test_af_unix_socket_input_is_rejected_before_any_read(self):
        data = json.dumps(synthetic_claim()).encode("utf-8")
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            left.sendall(data)
            child = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                stdin=right, capture_output=True, timeout=5, check=False,
            )
        finally:
            left.close()
            right.close()
        self.assertEqual(child.returncode, 2)
        self.assert_hold(json.loads(child.stdout))
        self.assertEqual(child.stderr, b"")

    def test_disconnected_local_receipt_reader_never_prints_traceback(self):
        data = json.dumps(synthetic_claim()).encode("utf-8")
        child = subprocess.Popen(
            [sys.executable, str(SCRIPT), "--stdin-json"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert child.stdout is not None
        child.stdout.close()
        _, err = child.communicate(input=data, timeout=5)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(err, b"")

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

    def test_real_subprocess_malformed_claims_have_identical_opaque_hold_bytes(self):
        secret = b"FICTIONAL-CLIENT-NEVER-ECHO-1437"
        base = synthetic_claim()
        malformed = [
            b"",
            b"null",
            b"{}",
            b"\xff",
            b" ",
            b"{" + b"X" * (mod.MAX_INPUT_BYTES + 1) + b"}",
            b'{"assets":[], "assets":[]}',
            b'{"as\\u0073ets":[]}',
            b'{"scope":"FICTIONAL-CLIENT-NEVER-ECHO-1437", "approved":true}',
            b'{"assets":["\\u0061pp.example.test"],"excluded_assets":[],"allowed_capabilities":["x"]}',
            b'{"assets":["EXAMPLE.TEST"],"excluded_assets":[],"allowed_capabilities":["x"]}',
            b'{"assets": ["api.example.test"], "excluded_assets": [], "allowed_capabilities": []}',
            b'{"assets": [], "excluded_assets": [], "allowed_capabilities": ["x"]}',
            b'{"assets":NaN,"excluded_assets":[],"allowed_capabilities":["x"]}',
            b'{"assets":["http://example.test"],"excluded_assets":[],"allowed_capabilities":["x"]}',
            b'{"assets":[false],"excluded_assets":[],"allowed_capabilities":["x"]}',
            json.dumps({**base, "approved": "FICTIONAL-CLIENT-NEVER-ECHO-1437"}).encode(),
            json.dumps({**base, "assets": ["FICTIONAL-CLIENT-NEVER-ECHO-1437"]}).encode(),
        ]
        expected = json.dumps({"status": "HOLD", **mod.FALSE_FLAGS},
                              sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for case in malformed:
            with self.subTest(malformed=case[:48]):
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    input=case, capture_output=True, timeout=5, check=False,
                )
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(proc.stdout, expected)
                self.assertNotIn(secret, proc.stdout)

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
