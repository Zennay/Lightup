"""True stdin JSON operator-review envelope regressions (issue #1495)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CMD = [sys.executable, "-m", "lightup.synthetic_scope_notice_cli_1495", "--synthetic-only"]
DATA = {
    "review_at": "2026-10-16T12:00:00Z",
    "proposals": [{
        "asset": "desk.example.test",
        "capability": "inventory_read",
        "risk": 4,
        "valid_from": "2026-10-16T11:00:00Z",
        "valid_until": "2026-10-16T13:00:00Z",
    }],
}


def process(*flags, data=None, raw=None):
    payload = raw if raw is not None else json.dumps(DATA if data is None else data).encode("utf-8")
    return subprocess.run(
        [*CMD, *flags], input=payload, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=12,
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )


class FictionalScopeJsonEnvelope1495(unittest.TestCase):
    def assert_no_authority(self, result):
        self.assertEqual(result["authorized"], False)
        self.assertEqual(result["consent_verified"], False)
        self.assertEqual(result["dispatch_allowed"], False)
        self.assertEqual(result["release_allowed"], False)
        self.assertIn("NOT AUTHORIZED", result["notice"])

    def test_json_success_is_review_only_but_never_exit_zero(self):
        p = process("--format", "json")
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertFalse(p.stderr)
        x = json.loads(p.stdout)
        self.assertEqual(x["status"], "REVIEW_ONLY")
        self.assertEqual(x["reviewed"], 1)
        self.assertTrue(x["elevated_risk"])
        self.assertIn("desk.example.test", x["notice"])
        self.assert_no_authority(x)

    def test_json_nl_requires_explicit_language_and_still_no_authority(self):
        p = process("--lang", "nl", "--format", "json")
        self.assertEqual(p.returncode, 2, p.stderr)
        x = json.loads(p.stdout)
        self.assertIn("NIET GEAUTORISEERD", x["notice"])
        self.assertIn("Geen klanttoestemming", x["notice"])
        self.assert_no_authority(x)

    def test_json_en_matches_default_text_meaning(self):
        default = json.loads(process("--format", "json").stdout)
        en = json.loads(process("--lang", "en", "--format", "json").stdout)
        self.assertEqual(default, en)
        self.assert_no_authority(default)

    def test_json_corrupt_input_is_hold_and_does_not_echo(self):
        p = process("--format", "json", raw=b'{"review_at": "BAD", "proposals": [{"asset": "private-data.example.com"}]}')
        self.assertEqual(p.returncode, 3)
        x = json.loads(p.stdout)
        self.assertEqual(x["status"], "HOLD")
        self.assertEqual(x["reviewed"], 0)
        self.assertFalse(x["elevated_risk"])
        self.assertNotIn("private-data.example.com", x["notice"])
        self.assert_no_authority(x)
        self.assertFalse(p.stderr)

    def test_json_highrisk_cannot_mark_approved_even_with_valid_values(self):
        for r in (4, 5):
            with self.subTest(risk=r):
                data = json.loads(json.dumps(DATA))
                data["proposals"][0]["risk"] = r
                p = process("--format", "json", data=data)
                self.assertEqual(p.returncode, 2)
                x = json.loads(p.stdout)
                self.assertTrue(x["elevated_risk"])
                self.assert_no_authority(x)

    def test_json_lowrisk_keeps_warning_and_false_authority(self):
        data = json.loads(json.dumps(DATA))
        data["proposals"][0]["risk"] = 1
        p = process("--format", "json", data=data)
        x = json.loads(p.stdout)
        self.assertEqual(p.returncode, 2)
        self.assertFalse(x["elevated_risk"])
        self.assertIn("human review", x["notice"])
        self.assert_no_authority(x)

    def test_json_duplicate_keys_hold_without_echo(self):
        payload = json.dumps(DATA).replace('"asset":', '"asset": "private-data.example.com", "asset":', 1).encode()
        p = process("--format", "json", raw=payload)
        self.assertEqual(p.returncode, 3)
        x = json.loads(p.stdout)
        self.assertEqual(x["status"], "HOLD")
        self.assertNotIn("private-data.example.com", x["notice"])
        self.assert_no_authority(x)

    def test_json_oversized_input_bounded_hold(self):
        p = process("--format", "json", raw=b"X" * 65537)
        self.assertEqual(p.returncode, 3)
        x = json.loads(p.stdout)
        self.assertEqual(x["status"], "HOLD")
        self.assert_no_authority(x)

    def test_json_canonical_permutation_invariant(self):
        data = json.loads(json.dumps(DATA))
        second = data["proposals"][0].copy()
        second["asset"] = "alpha.example.test"
        data["proposals"].append(second)
        x = process("--format", "json", data=data)
        data["proposals"].reverse()
        y = process("--format", "json", data=data)
        self.assertEqual(x.returncode, 2)
        self.assertEqual(y.returncode, 2)
        self.assertEqual(x.stdout, y.stdout)
        self.assert_no_authority(json.loads(x.stdout))

    def test_json_format_flag_order_is_explicit_only(self):
        invalid = (("--format", "JSON"), ("--format", "text"),
                   ("--format=json",), ("--format", "json", "--lang", "nl"),
                   ("--lang", "en", "--format"), ("--format", "json", "--scan"))
        for flags in invalid:
            with self.subTest(flags=flags):
                p = process(*flags)
                self.assertEqual(p.returncode, 3)
                self.assertIn(b"NOT AUTHORIZED", p.stdout)
                self.assertNotIn(b"desk.example.test", p.stdout)

    def test_json_output_is_single_serialized_line(self):
        p = process("--format", "json")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(len(p.stdout.splitlines()), 1)
        self.assertTrue(p.stdout.startswith(b"{"))
        self.assert_no_authority(json.loads(p.stdout))

    def test_json_machine_envelope_contains_exact_expected_keys(self):
        result = json.loads(process("--format", "json").stdout)
        self.assertEqual(set(result), {
            "status", "notice", "reviewed", "elevated_risk",
            "authorized", "consent_verified", "dispatch_allowed", "release_allowed",
        })


if __name__ == "__main__":
    unittest.main()
