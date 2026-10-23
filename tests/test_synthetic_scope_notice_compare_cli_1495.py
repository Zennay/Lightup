"""Real CLI-to-CLI offline fictional pair HTML comparison acceptance #1495."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
ORIGIN = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495",
          "--synthetic-only", "--format", "json"]
COMPARE = [sys.executable, "-m", "lightup.synthetic_scope_notice_compare_cli_1495"]

AT = "2026-10-16T12:00:00Z"


def proposal(asset="desk.example.test", risk=2):
    return dict(asset=asset, capability="inventory_read", risk=risk,
                valid_from="2026-10-16T11:00:00Z", valid_until="2026-10-16T13:00:00Z")


def process(cmd, raw):
    return subprocess.run(cmd, input=raw, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=ROOT, env=ENV,
                          timeout=16, check=False)


def generate(*entries):
    data = dict(review_at=AT, proposals=list(entries))
    res = process(ORIGIN, json.dumps(data).encode())
    assert res.returncode == 2, res.stderr
    return json.loads(res.stdout)


def pair(*, before=None, after=None):
    return json.dumps({
        "before": generate(proposal()) if before is None else before,
        "after": generate(proposal(risk=5)) if after is None else after,
    }).encode()


class FictionalPairCli1495(unittest.TestCase):
    def review(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, b"")
        html = result.stdout.decode("utf-8")
        self.assertIn("<!doctype html>", html)
        self.assertIn("NOT AUTHORIZED", html)
        self.assertIn("REVIEW_ONLY", html)
        self.assertIn("authorized=false", html)
        self.assertIn("consent_verified=false", html)
        self.assertIn("dispatch_allowed=false", html)
        self.assertIn("release_allowed=false", html)
        self.assertIn("default-src 'none'", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("href=", html)
        self.assertNotIn("<form", html)
        self.assertEqual(html.count("PENDING —"), 4)
        return html

    def hold(self, result):
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stderr, b"")
        html = result.stdout.decode("utf-8")
        self.assertIn("HOLD", html)
        self.assertIn("NOT AUTHORIZED", html)
        self.assertNotIn("<table", html)
        self.assertNotIn("PENDING —", html)
        self.assertIn("authorized=false", html)
        self.assertNotIn("desk.example.test", html)
        self.assertNotIn("customer.example.com", html)
        return html

    def test_committed_comparison_fixtures_run_end_to_end(self):
        before = (ROOT/"examples"/"fictional_scope_compare_before_1495.json").read_bytes()
        after = (ROOT/"examples"/"fictional_scope_compare_after_1495.json").read_bytes()
        left = process(ORIGIN, before)
        right = process(ORIGIN, after)
        self.assertEqual(left.returncode, 2, left.stderr)
        self.assertEqual(right.returncode, 2, right.stderr)
        combined = json.dumps({
            "before": json.loads(left.stdout),
            "after": json.loads(right.stdout),
        }).encode()
        page = self.review(process([*COMPARE, "--synthetic-pair-to-html"], combined))
        self.assertIn("PROPOSED DETAILS CHANGED", page)
        self.assertIn("ONLY IN AFTER — NOT GRANTED", page)
        self.assertIn("metadata_read", page)
        self.assertIn("5/5", page)
        self.assertIn("2026-10-16T12:45:00Z", page)
        self.assertIn("Proposed changed pairs: 2", page)

    def test_exact_example_inputs_are_reserved_dns_and_bounded(self):
        for name in ("fictional_scope_compare_before_1495.json",
                     "fictional_scope_compare_after_1495.json"):
            with self.subTest(name=name):
                document = json.loads((ROOT/"examples"/name).read_text())
                self.assertIn("review_at", document)
                self.assertTrue(1 <= len(document["proposals"]) <= 32)
                for item in document["proposals"]:
                    self.assertTrue(item["asset"].endswith(".example.test"))
                    self.assertTrue(1 <= item["risk"] <= 5)
                    self.assertNotIn("http", item["asset"])
                    self.assertNotIn("://", item["asset"])
                p = process(ORIGIN, json.dumps(document).encode())
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertNotIn(b'"authorized":true', p.stdout)

    def test_genuine_three_process_full_example_delta(self):
        data = pair()
        page = self.review(process([*COMPARE, "--synthetic-pair-to-html"], data))
        self.assertIn("PROPOSED DETAILS CHANGED", page)
        self.assertIn("5/5", page)

    def test_genuine_three_process_added_fictional_asset(self):
        a = generate(proposal())
        b = generate(proposal(), proposal("another.example.test"))
        html = self.review(process([*COMPARE, "--synthetic-pair-to-html"], pair(before=a, after=b)))
        self.assertIn("NOT GRANTED", html)
        self.assertIn("another.example.test", html)

    def test_three_process_removed_is_not_real_revocation(self):
        a = generate(proposal(), proposal("another.example.test"))
        b = generate(proposal())
        html = self.review(process([*COMPARE, "--synthetic-pair-to-html"], pair(before=a, after=b)))
        self.assertIn("NOT REVOKED", html)

    def test_identical_real_reports_are_read_only(self):
        original = generate(proposal())
        html = self.review(process([*COMPARE, "--synthetic-pair-to-html"],
                                   pair(before=original, after=original)))
        self.assertIn("IDENTICAL FICTIONAL ENTRY", html)

    def test_empty_input_is_generic_hold(self):
        self.hold(process([*COMPARE, "--synthetic-pair-to-html"], b""))

    def test_invalid_non_json_is_generic_hold_without_echo(self):
        self.hold(process([*COMPARE, "--synthetic-pair-to-html"], b"not json customer.example.com"))

    def test_too_large_payload_bounded_hold(self):
        self.hold(process([*COMPARE, "--synthetic-pair-to-html"], b"x"*131073))

    def test_bad_nested_grant_claim_denied_atomically(self):
        a, b = generate(proposal()), generate(proposal("another.example.test"))
        b["dispatch_allowed"] = True
        page = self.hold(process([*COMPARE, "--synthetic-pair-to-html"],
                                 pair(before=a, after=b)))
        self.assertNotIn("another.example.test", page)

    def test_real_target_added_to_after_is_not_echoed(self):
        a, b = generate(proposal()), generate(proposal())
        b["notice"] = b["notice"].replace("desk.example.test", "customer.example.com")
        self.hold(process([*COMPARE, "--synthetic-pair-to-html"],
                          pair(before=a, after=b)))

    def test_missing_explicit_opt_in_denies_without_reading_scope(self):
        self.hold(process(COMPARE, pair()))

    def test_extra_or_misordered_flags_denied(self):
        for flags in (("--synthetic-pair-to-html", "--scan"),
                      ("--synthetic-only",), ("--format", "html"),
                      ("--synthetic-pair-to-html=true",)):
            with self.subTest(flags=flags):
                self.hold(process([*COMPARE, *flags], pair()))

    def test_secret_flag_not_reflected_back(self):
        flag = "--customer-secret-12345"
        html = self.hold(process([*COMPARE, flag], pair()))
        self.assertNotIn(flag, html)

    def test_valid_or_invalid_never_exit_zero(self):
        for payload, flags in ((pair(), ("--synthetic-pair-to-html",)),
                               (b"{}", ("--synthetic-pair-to-html",)),
                               (pair(), ())):
            with self.subTest(flags=flags):
                res = process([*COMPARE, *flags], payload)
                self.assertIn(res.returncode, (2, 3))
                self.assertNotEqual(res.returncode, 0)

    def test_deterministic_from_same_real_sources(self):
        raw = pair()
        a = process([*COMPARE, "--synthetic-pair-to-html"], raw)
        b = process([*COMPARE, "--synthetic-pair-to-html"], raw)
        self.assertEqual(a.stdout, b.stdout)
        self.review(a)


if __name__ == "__main__":
    unittest.main()
