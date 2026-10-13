"""Subprocess-level proof: optional local intake never invokes model/provider/target."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_remediation_review_intake_optin.py"


def _finding(refs=None):
    return {
        "finding": "Private synthetic title",
        "severity": "medium",
        "impact": "Private synthetic impact",
        "target": "asset://synthetic-private-host",
        "fix": "Private synthetic remediation",
        "evidence_summary": "Private synthetic evidence summary",
        "evidence_ids": ["secret:123-should-not-log"] if refs is None else refs,
        "evidence_payload": "SENSITIVE-SYNTHETIC-RAW-DO-NOT-ECHO",
    }


def _fixture(*findings):
    return {
        "findings": list(findings),
        "target": "asset://synthetic-private-host",
        "evidence_payload": "SENSITIVE-TOPLEVEL-DO-NOT-ECHO",
    }


def _bytes(value):
    return json.dumps(value, ensure_ascii=True).encode("utf-8")


class RemediationIntakeCliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fixture.json"

    def _execute(self, content=None, *, path=None):
        if content is not None:
            self.path.write_bytes(content)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--input", str(path or self.path)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def _parse(self, response, expected_exit):
        self.assertEqual(response.returncode, expected_exit, response.stderr)
        self.assertEqual(response.stderr, "")
        obj = json.loads(response.stdout)
        self.assertIs(type(obj), dict)
        for forbidden in (
            "Private synthetic", "asset://", "secret:123",
            "SENSITIVE-", "evidence_payload", "traceback",
            "Traceback", "input_path",
        ):
            self.assertNotIn(forbidden, response.stdout)
        self.assertIs(obj["model_dispatched"], False)
        self.assertIs(obj["authorized"], False)
        return obj

    def test_synthetic_canonical_fixture_reports_counts_only(self):
        output = self._parse(self._execute(_bytes(_fixture(_finding()))), 0)
        self.assertEqual(output, {
            "status": "ready", "finding_count": 1, "evidence_reference_count": 1,
            "metadata_only": True, "model_dispatched": False, "authorized": False,
        })

    def test_multiple_findings_and_fallback_counts(self):
        payload = _fixture(_finding(), _finding(["ref:one", "ref:two"]))
        payload["findings"][0].pop("evidence_ids")
        payload["evidence_id"] = "fallback:opaque"
        output = self._parse(self._execute(_bytes(payload)), 0)
        self.assertEqual(output["finding_count"], 2)
        self.assertEqual(output["evidence_reference_count"], 3)

    def test_empty_finding_batch_is_not_authorization(self):
        output = self._parse(self._execute(_bytes(_fixture())), 0)
        self.assertEqual(output["finding_count"], 0)
        self.assertIs(output["authorized"], False)

    def test_late_invalid_remediation_never_emits_partial_counts(self):
        payload = _fixture(_finding(), _finding())
        payload["findings"][1]["fix"] = " "
        out = self._parse(self._execute(_bytes(payload)), 2)
        self.assertEqual(out["code"], "invalid_review_metadata")
        self.assertNotIn("finding_count", out)

    def test_duplicate_evidence_fails_closed(self):
        out = self._parse(self._execute(
            _bytes(_fixture(_finding(["ref:one", "ref:one"])))
        ), 2)
        self.assertEqual(out["code"], "invalid_review_metadata")

    def test_duplicate_json_keys_not_silently_last_write_wins(self):
        blob = b'{"findings":[],"findings":[{"fix":"SENSITIVE-NOT-FORWARDED"}]}'
        out = self._parse(self._execute(blob), 2)
        self.assertEqual(out["code"], "duplicate_json_key")

    def test_nested_duplicate_json_keys_fail_closed(self):
        blob = b'{"findings":[],"nested":{"secret":"1","secret":"2"}}'
        out = self._parse(self._execute(blob), 2)
        self.assertEqual(out["code"], "duplicate_json_key")

    def test_nonstandard_nan_infinity_rejected(self):
        for symbol in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=symbol):
                raw = ('{"findings":[],"untrusted":' + symbol + '}').encode()
                out = self._parse(self._execute(raw), 2)
                self.assertEqual(out["code"], "nonstandard_json_constant")

    def test_extreme_exponent_is_rejected(self):
        out = self._parse(
            self._execute(b'{"findings":[],"untrusted":1e9999}'), 2
        )
        self.assertEqual(out["code"], "nonfinite_json_number")

    def test_invalid_utf8_rejected_without_dumping_bytes(self):
        out = self._parse(self._execute(b'{"findings":[],"secret":"\xff"}'), 2)
        self.assertEqual(out["code"], "invalid_utf8")

    def test_invalid_json_rejected_without_exception_details(self):
        out = self._parse(self._execute(b'{"findings": [} SENSITIVE-RAW'), 2)
        self.assertEqual(out["code"], "invalid_json")

    def test_non_object_json_is_rejected(self):
        for raw in (b'null', b'[]', b'42', b'"raw-secret"', b'true'):
            with self.subTest(raw=raw):
                out = self._parse(self._execute(raw), 2)
                self.assertEqual(out["code"], "invalid_review_metadata")

    def test_raw_file_byte_budget(self):
        raw = b'{"findings":[],"padding":"' + b'x' * 1_048_577 + b'"}'
        out = self._parse(self._execute(raw), 2)
        self.assertEqual(out["code"], "input_too_large")

    def test_nonexistent_file_is_rejected_without_filepath_leak(self):
        nonexistent = Path(self.tmp.name) / "private-synthetic-file-name.json"
        out = self._parse(self._execute(path=nonexistent), 2)
        self.assertEqual(out["code"], "invalid_local_file")
        self.assertNotIn(nonexistent.name, str(out))

    def test_symlink_not_followed(self):
        self.path.write_bytes(_bytes(_fixture()))
        symlink = Path(self.tmp.name) / "linked.json"
        symlink.symlink_to(self.path)
        out = self._parse(self._execute(path=symlink), 2)
        self.assertEqual(out["code"], "invalid_local_file")

    def test_unicode_surrogate_rejected_as_metadata(self):
        payload = _fixture(_finding())
        payload["findings"][0]["fix"] = "invalid \ud800 synthetic"
        out = self._parse(self._execute(_bytes(payload)), 2)
        self.assertEqual(out["code"], "invalid_review_metadata")

    def test_refuse_unbounded_evidence_reference_list(self):
        payload = _fixture(_finding([f"ref:{i}" for i in range(65)]))
        out = self._parse(self._execute(_bytes(payload)), 2)
        self.assertEqual(out["code"], "invalid_review_metadata")


    def test_excessively_nested_json_is_classified_without_traceback(self):
        raw = (b'{"findings":[],"untrusted":'
               + b'[' * 2200 + b'0' + b']' * 2200 + b'}')
        out = self._parse(self._execute(raw), 2)
        self.assertEqual(out["code"], "invalid_json")


if __name__ == "__main__":
    unittest.main()
