"""Hostile JSON + real subprocess CLI contract tests, offline only (#1487).

The subprocesses are local Python interpreter invocations with captured streams.
No LightUp network clients, tools, targets, grants or production handlers.
"""
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from lightup.lab_session_lineage_cli_1487 import review_synthetic_json


NOW = "2030-01-01T12:00:00Z"


def sample(**overrides):
    record = {
        "lab_reference": "LAB-OFFLINE-001",
        "operator_id": "ACTOR-FICTIONAL-001",
        "session_id": "SESSION-FICTIONAL-001",
        "engagement_id": "ENG-FICTIONAL-001",
        "asset_id": "ASSET-LOOPBACK-001",
        "capability_id": "CAP-REVIEW-ONLY",
        "starts_at": "2030-01-01T11:00:00Z",
        "expires_at": "2030-01-01T13:00:00Z",
        "revoked": False,
    }
    record.update(overrides)
    return json.dumps(
        {"assessment_time": NOW, "claims": [record]}, separators=(",", ":")
    ).encode("utf-8")


class DeepJsonCliBoundaries1487(unittest.TestCase):
    @staticmethod
    def subprocess_preview(payload: bytes, *arguments: str):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(root, "src")
        env["PYTHONNOUSERSITE"] = "1"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "lightup.lab_session_lineage_cli_1487",
                *arguments,
            ],
            cwd=root,
            env=env,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    def assert_private_holding(self, text):
        self.assertEqual(text, "HOLD")
        self.assertNotIn("ACTOR-", text)
        self.assertNotIn("ASSET-", text)
        self.assertNotIn("LAB-", text)

    def test_too_deep_array_fails_closed_without_python_recursion_traceback(self):
        payload = ("[" * 1500 + "0" + "]" * 1500).encode()
        self.assertLess(len(payload), 16384)
        self.assert_private_holding(review_synthetic_json(payload))

    def test_too_deep_object_fails_closed_without_python_recursion_traceback(self):
        payload = ("{" + '"a":{' * 1500 + '"a":0' + "}" * 1501).encode()
        self.assertLess(len(payload), 16384)
        self.assert_private_holding(review_synthetic_json(payload))

    def test_too_deep_array_inside_claims_does_not_escape_parser(self):
        payload = (
            '{"assessment_time":"' + NOW + '","claims":'
            + "[" * 1500 + "0" + "]" * 1500 + "}"
        ).encode()
        self.assertLess(len(payload), 16384)
        self.assert_private_holding(review_synthetic_json(payload))

    def test_mocked_recursion_error_is_quarantined(self):
        with patch(
            "lightup.lab_session_lineage_cli_1487.json.loads",
            side_effect=RecursionError("private-actor-should-not-leak"),
        ):
            self.assert_private_holding(review_synthetic_json(sample()))

    def test_escaped_duplicate_json_key_is_rejected(self):
        base = sample().decode("utf-8")
        duplicate = base[:-1] + ',"cl\\u0061ims":[]}'
        self.assert_private_holding(review_synthetic_json(duplicate.encode()))

    def test_escaped_duplicate_claim_field_is_rejected(self):
        base = sample().decode("utf-8")
        duplicate = base.replace(
            '"revoked":false',
            '"revoked":false,"rev\\u006fked":false',
            1,
        )
        self.assert_private_holding(review_synthetic_json(duplicate.encode()))

    def test_invalid_bytes_in_schema_are_quarantined(self):
        for payload in (b'{"claims":\xed\xa0\x80}', b"\xff" + sample(), b"{\xc0\xaf}"):
            self.assert_private_holding(review_synthetic_json(payload))

    def test_valid_synthetic_claim_review_is_not_authority(self):
        self.assertEqual(review_synthetic_json(sample()), "REVIEW_ONLY")
        self.assertEqual(review_synthetic_json(sample(revoked=True)), "HOLD")

    def test_direct_subprocess_valid_claim_has_nonzero_review_exit(self):
        result = self.subprocess_preview(sample(), "--synthetic-only")
        self.assertEqual(result.returncode, 3)
        self.assertFalse(result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "REVIEW_ONLY")
        self.assertIs(parsed["synthetic_only"], True)
        for key in (
            "grants_authority", "can_issue_permit", "can_dispatch", "can_release"
        ):
            self.assertIs(parsed[key], False)
        self.assertNotIn(b"ACTOR-", result.stdout)

    def test_direct_subprocess_nested_json_returns_hold_not_traceback(self):
        payload = ("[" * 1500 + "0" + "]" * 1500).encode()
        result = self.subprocess_preview(payload, "--synthetic-only")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_direct_subprocess_revoked_claim_returns_hold(self):
        result = self.subprocess_preview(sample(revoked=True), "--synthetic-only")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_direct_subprocess_denies_missing_synthetic_flag(self):
        result = self.subprocess_preview(sample())
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_direct_subprocess_rejects_paths_and_unknown_args(self):
        for flag in ("--file=/private/operator", "--asset=example.test", "--help"):
            with self.subTest(flag=flag):
                result = self.subprocess_preview(sample(), flag)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "HOLD")
                self.assertNotIn(flag.encode(), result.stdout)

    def test_direct_subprocess_limit_truncates_and_holds_oversized_stdin(self):
        raw = sample() + b" " * 20000
        result = self.subprocess_preview(raw, "--synthetic-only")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "HOLD")

    def test_determinism_repeated_local_process_does_not_share_history(self):
        # Positive *shape* review is reproducible: it has NO durable replay ledger.
        first = self.subprocess_preview(sample(), "--synthetic-only")
        second = self.subprocess_preview(sample(), "--synthetic-only")
        self.assertEqual(first.returncode, 3)
        self.assertEqual(second.returncode, 3)
        self.assertEqual(first.stdout, second.stdout)
        self.assertFalse(first.stderr + second.stderr)
        # Repeated REVIEW_ONLY therefore CANNOT be interpreted as consent.


if __name__ == "__main__":
    unittest.main()
