"""Synthetic, offline scope metadata review tests. No targets or grants."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import random
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
