"""Synthetic and subprocess acceptance for the non-authorizing #1093 reviewer."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "review_scope_destination_schema_1093_offline.py"
sys.path.insert(0, str(ROOT / "scripts"))
from review_scope_destination_schema_1093_offline import (  # noqa: E402
    DENIAL, MAX_INPUT_BYTES, review_bytes, review_schema,
)


def fixture():
    return {"tools": [
        {"tool_id": "lab-http-baseline", "parameters": [
            {"name": "url", "kind": "string", "role": "endpoint"}]},
        {"tool_id": "lab-tls-baseline", "parameters": [
            {"name": "host", "kind": "string", "role": "host"},
            {"name": "port", "kind": "integer", "role": "port"}]},
        {"tool_id": "lab-service-inventory", "parameters": [
            {"name": "host", "kind": "string", "role": "host"},
            {"name": "ports", "kind": "string", "role": "port_set"}]},
    ]}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ReviewTests(unittest.TestCase):
    def assert_denied(self, value, status):
        self.assertEqual(value["status"], status)
        self.assertEqual(set(value), {"status", "claimed_tool_count",
                                     "claimed_parameter_count", *DENIAL})
        for key in DENIAL:
            self.assertIs(value[key], False)
        for key in ("claimed_tool_count", "claimed_parameter_count"):
            self.assertIs(type(value[key]), int)

    def test_three_distinct_real_worker_shapes_structural_only(self):
        value = review_bytes(encoded(fixture()))
        self.assert_denied(value, "REVIEW_ONLY")
        self.assertEqual((value["claimed_tool_count"], value["claimed_parameter_count"]), (3, 5))

    def test_no_source_truth_can_be_inferred(self):
        fake = fixture()
        fake["tools"][0]["tool_id"] = "unknown_but_well_formed"
        self.assert_denied(review_schema(fake), "REVIEW_ONLY")

    def test_reject_role_kind_cross_product(self):
        for role, wrong_kind in (("port", "string"), ("port_set", "integer"),
                                 ("host", "integer"), ("endpoint", "array")):
            with self.subTest(role=role):
                sample = fixture()
                sample["tools"][0]["parameters"][0].update(role=role, kind=wrong_kind)
                self.assert_denied(review_schema(sample), "HOLD")

    def test_reject_untrusted_structure(self):
        for change in (
            lambda v: v.update(approved=True),
            lambda v: v["tools"][0].update(approved=True),
            lambda v: v["tools"][0]["parameters"][0].update(approved=True),
            lambda v: v["tools"].append(v["tools"][0]),
            lambda v: v["tools"][0]["parameters"].append(v["tools"][0]["parameters"][0]),
            lambda v: v["tools"][0]["parameters"][0].update(role="authorized"),
            lambda v: v["tools"][0]["parameters"][0].update(name="Url"),
            lambda v: v["tools"][0]["parameters"][0].update(kind=True),
            lambda v: v["tools"][0].update(tool_id="HTTP-Baseline"),
            lambda v: v["tools"][0].update(parameters=[]),
            lambda v: v["tools"][0]["parameters"][0].update(role="none"),
        ):
            with self.subTest(case=str(change)):
                sample = fixture()
                change(sample)
                self.assert_denied(review_schema(sample), "HOLD")

    def test_real_lab_worker_id_hyphens_are_allowed_but_parameter_hyphens_denied(self):
        sample = fixture()
        self.assert_denied(review_schema(sample), "REVIEW_ONLY")
        sample["tools"][0]["parameters"][0]["name"] = "bad-parameter"
        self.assert_denied(review_schema(sample), "HOLD")

    def test_current_paramkind_enum_is_closed_world(self):
        for kind in ("array", "object", "map", "STRING", "float"):
            with self.subTest(kind=kind):
                sample = fixture()
                sample["tools"][1]["parameters"][1]["kind"] = kind
                self.assert_denied(review_schema(sample), "HOLD")

    def test_non_destination_metadata_does_not_supply_authority(self):
        sample = fixture()
        sample["tools"][0]["parameters"].append(
            {"name": "max_retries", "kind": "integer", "role": "none"})
        self.assert_denied(review_schema(sample), "REVIEW_ONLY")
        sample["tools"][0]["parameters"][0]["role"] = "none"
        self.assert_denied(review_schema(sample), "HOLD")

    def test_duplicate_decoded_keys_rejected(self):
        for raw in (
            b'{"tools":[],"tools":[]}',
            b'{"tools":[{"tool_id":"a","tool_id":"b","parameters":[]}]}',
            b'{"tools":[],"\\u0074ools":[]}',
            b'{"tools":NaN}',
            b'{"tools":Infinity}',
            b'{"tools":1e9999}',
            b'{"tools":[] }{}',
            b'\xff',
            b'',
            b' ' * (MAX_INPUT_BYTES + 1),
        ):
            with self.subTest(raw=raw[:30]):
                self.assert_denied(review_bytes(raw), "HOLD")

    def test_reject_polymorphic_in_memory_claims(self):
        class Text(str):
            pass
        class Items(list):
            pass
        for value in (Items(fixture()["tools"]),):
            self.assert_denied(review_schema({"tools": value}), "HOLD")
        sample = fixture()
        sample["tools"][0]["tool_id"] = Text("lab-http-baseline")
        self.assert_denied(review_schema(sample), "HOLD")
        sample = fixture()
        sample["tools"][0]["parameters"][0]["role"] = Text("endpoint")
        self.assert_denied(review_schema(sample), "HOLD")

    def test_max_structural_cardinality(self):
        data = fixture()["tools"][0]
        many = {"tools": [{"tool_id": "tool_" + str(i), "parameters":
                 [{"name": "host", "kind": "string", "role": "host"}]}
                for i in range(8)]}
        self.assert_denied(review_schema(many), "REVIEW_ONLY")
        many["tools"].append(data)
        self.assert_denied(review_schema(many), "HOLD")
        many = {"tools": [{"tool_id": "one", "parameters":
                 [{"name": "p_" + str(i), "kind": "string", "role": "host"}
                  for i in range(16)]}]}
        self.assert_denied(review_schema(many), "REVIEW_ONLY")
        many["tools"][0]["parameters"].append(data["parameters"][0])
        self.assert_denied(review_schema(many), "HOLD")

    def test_cli_unclosed_pipe_forces_finite_atomic_hold(self):
        for payload in (b'{"tools":[', encoded(fixture())):
            with self.subTest(length=len(payload)):
                proc = subprocess.Popen(
                    [sys.executable, str(SCRIPT), "--stdin-json"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    proc.stdin.write(payload)
                    proc.stdin.flush()  # deliberately do NOT send EOF
                    self.assertEqual(proc.wait(timeout=6), 2)
                    stdout = proc.stdout.read()
                    stderr = proc.stderr.read()
                    self.assertFalse(stderr)
                    self.assertEqual(stdout.count(b"\n"), 1)
                    self.assert_denied(json.loads(stdout), "HOLD")
                    self.assertNotIn(payload, stdout)
                finally:
                    proc.stdin.close()
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=3)
                    proc.stdout.close()
                    proc.stderr.close()

    def test_cli_rejects_regular_file_stdin_without_reading_it(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(encoded(fixture()))
            stream.flush()
            stream.seek(0)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin-json"],
                stdin=stream, capture_output=True, timeout=6)
            self.assertEqual(result.returncode, 2)
            self.assert_denied(json.loads(result.stdout), "HOLD")
            self.assertEqual(stream.tell(), 0)
            self.assertFalse(result.stderr)

    def test_cli_real_process_never_exits_success_and_never_echoes_claims(self):
        sample = fixture()
        sample["tools"][0]["tool_id"] = "private_customer_token"
        for raw, argv, status, code in (
            (encoded(sample), ["--stdin-json"], "REVIEW_ONLY", 3),
            (b'{"tools":"SECRET-NEVER-ECHO"}', ["--stdin-json"], "HOLD", 2),
            (encoded(sample), ["--approved"], "HOLD", 2),
            (encoded(sample), ["--stdin-json", "--release"], "HOLD", 2),
        ):
            with self.subTest(status=status):
                result = subprocess.run([sys.executable, str(SCRIPT), *argv],
                                        input=raw, capture_output=True, timeout=6)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertFalse(result.stderr)
                self.assertEqual(result.stdout.count(b"\n"), 1)
                self.assertLess(len(result.stdout), 512)
                self.assertNotIn(b"private_customer_token", result.stdout)
                self.assertNotIn(b"SECRET-NEVER-ECHO", result.stdout)
                self.assert_denied(json.loads(result.stdout), status)


if __name__ == "__main__":
    unittest.main()
