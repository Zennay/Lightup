"""Synthetic subprocess and in-process proof; no installed authorization path."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scope_release_dependency_inventory_20261015.py"
module_spec = importlib.util.spec_from_file_location("gate_inventory", SCRIPT)
review = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(review)


def packet(value="MISSING"):
    return {"schema": 1, "checks": {name: value for name in review.GATES}}


class GateInventoryTests(unittest.TestCase):
    def assert_held(self, result):
        self.assertEqual(result["status"], "HOLD")
        for name in review.FLAGS:
            self.assertIs(result[name], False)
        self.assertNotIn("READY", json.dumps(result))

    def cli(self, raw):
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=raw,
                              capture_output=True, timeout=5, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b"")
        result = json.loads(proc.stdout)
        self.assert_held(result)
        return result

    def test_all_missing(self):
        result = review.assess(json.dumps(packet()).encode())
        self.assert_held(result)
        self.assertEqual(result["needs_attention"], list(review.GATES))

    def test_self_reported_still_requires_independent_review(self):
        result = self.cli(json.dumps(packet("SELF_REPORTED")).encode())
        self.assertEqual(result["self_reported_count"], len(review.GATES))
        self.assertEqual(result["provenance"], "SELF_ASSERTED_UNVERIFIED")
        self.assertEqual(result["needs_attention"], [])

    def test_mixed_gates_sorted_canonically(self):
        value = packet("SELF_REPORTED")
        value["checks"][review.GATES[4]] = "BLOCKED"
        value["checks"][review.GATES[0]] = "MISSING"
        value["checks"] = dict(reversed(tuple(value["checks"].items())))
        result = self.cli(json.dumps(value).encode())
        self.assertEqual(result["needs_attention"], [review.GATES[0], review.GATES[4]])

    def test_each_gate_missing_produces_attention(self):
        for gate in review.GATES:
            with self.subTest(gate=gate):
                value = packet("SELF_REPORTED")
                value["checks"][gate] = "BLOCKED"
                result = review.assess(json.dumps(value).encode())
                self.assertEqual(result["needs_attention"], [gate])
                self.assert_held(result)

    def test_malformed_inputs_fail_atomic_generic(self):
        valid = json.dumps(packet()).encode()
        malformed = [b"", b"[]", b"null", b"{}", b"{", b"\xff", b"\xef\xbb\xbf" + valid,
                     valid + b"{}", b" " * (review.MAX_BYTES + 1),
                     b'{"schema":1,"schema":1,"checks":{}}',
                     b'{"schema":NaN,"checks":{}}',
                     b'{"schema":1e999,"checks":{}}']
        control = self.cli(b"invalid")
        for raw in malformed:
            with self.subTest(raw=raw[:40]):
                self.assertEqual(self.cli(raw), control)

    def test_invalid_check_shape_is_generic(self):
        for replacement in [None, [], {}, {"client_consent": "SELF_REPORTED"},
                            {**packet()["checks"], "extra": "MISSING"}]:
            with self.subTest(replacement=type(replacement).__name__):
                value = packet()
                value["checks"] = replacement
                result = self.cli(json.dumps(value).encode())
                self.assertEqual(result["reason_code"], "INVALID_OR_INCOMPLETE_PACKET")

    def test_reject_nonliteral_statuses_and_extras(self):
        for invalid in [True, 1, "VERIFIED", "PASS", "RELEASE", "self_reported", " SELF_REPORTED"]:
            value = packet()
            value["checks"][review.GATES[0]] = invalid
            self.assertEqual(self.cli(json.dumps(value).encode())["self_reported_count"], 0)

    def test_reject_bool_as_schema_version(self):
        value = packet()
        value["schema"] = True
        self.assertEqual(self.cli(json.dumps(value).encode())["reason_code"],
                         "INVALID_OR_INCOMPLETE_PACKET")

    def test_nested_duplicate_key_is_rejected(self):
        raw = (b'{"schema":1,"checks":{' +
               b'"client_consent":"MISSING","client_consent":"SELF_REPORTED"}}')
        self.assertEqual(self.cli(raw)["self_reported_count"], 0)

    def test_no_echo_of_claimed_secrets(self):
        secret = "FICTIONAL_PRIVATE_NOTE_CANARY_22974"
        value = packet()
        value["secret"] = secret
        proc = subprocess.run([sys.executable, str(SCRIPT)],
                              input=json.dumps(value).encode(), capture_output=True,
                              timeout=5, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(secret.encode(), proc.stdout + proc.stderr)
        self.assert_held(json.loads(proc.stdout))

    def test_maximum_inclusive_byte_budget(self):
        payload = json.dumps(packet()).encode()
        self.assertLess(len(payload), review.MAX_BYTES)
        self.assertEqual(review.assess(payload)["status"], "HOLD")
        self.assertEqual(self.cli(payload + b" " * (review.MAX_BYTES + 1))["self_reported_count"], 0)

    def test_reject_in_memory_polymorphic_data(self):
        class BytesSubclass(bytes):
            pass
        with self.assertRaises(review.InvalidPacket):
            review.assess(BytesSubclass(json.dumps(packet()).encode()))


    def test_repo_fictional_fixture_is_always_non_authorizing(self):
        fixture = (SCRIPT.parents[1] / "docs" / "fixtures" /
                   "scope-release-fictional-packet-20261015.json").read_bytes()
        result = self.cli(fixture)
        self.assertEqual(result["self_reported_count"], 1)
        self.assertEqual(len(result["needs_attention"]), len(review.GATES) - 1)


if __name__ == "__main__":
    unittest.main()
