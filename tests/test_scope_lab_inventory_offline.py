"""Genuine stdlib synthetic acceptance for opt-in lab inventory shape checks."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_inventory_offline import (
    MAX_MANIFEST_BYTES, parse_document, review_inventory,
)

SCRIPT = ROOT / "scripts" / "check_scope_lab_inventory_offline.py"
FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)


def packet(declared=None, proposed=None):
    return {
        "schema_version": 1,
        "declared_lab_literals": (["127.0.0.1", "10.1.2.3", "fd00::1"]
                                  if declared is None else declared),
        "proposed_literals": ["10.1.2.3"] if proposed is None else proposed,
    }


class LabInventoryShapeReviewTests(unittest.TestCase):
    def assertNoAuthority(self, result):
        self.assertEqual(set(result), {"schema_version", "status", "reason", *FIELDS})
        self.assertEqual(result["schema_version"], 1)
        self.assertTrue(all(result[f] is False for f in FIELDS))
        self.assertNotIn("10.1.2.3", json.dumps(result))

    def test_explicit_single_matching_literal_shape_only(self):
        result = review_inventory(packet())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_all_declared_can_be_proposed_but_not_authorized(self):
        result = review_inventory(packet(proposed=["127.0.0.1", "10.1.2.3", "fd00::1"]))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_new_or_undeclared_address_holds_everything(self):
        result = review_inventory(packet(proposed=["10.1.2.3", "10.1.2.4"]))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "UNDECLARED_LITERAL")
        self.assertNoAuthority(result)

    def test_empty_inventory_or_proposed_set_holds(self):
        for declared, proposed in (([], ["127.0.0.1"]), (["127.0.0.1"], []),
                                   ([], [])):
            with self.subTest(declared=declared, proposed=proposed):
                result = review_inventory(packet(declared, proposed))
                self.assertEqual(result["status"], "HOLD")
                self.assertNoAuthority(result)

    def test_rejects_duplicate_declarations_or_proposals(self):
        for d, p in (
            (["10.1.2.3", "10.1.2.3"], ["10.1.2.3"]),
            (["10.1.2.3"], ["10.1.2.3", "10.1.2.3"]),
        ):
            self.assertEqual(review_inventory(packet(d, p))["status"], "HOLD")

    def test_rejects_undeclared_reserved_public_and_linklocal(self):
        unsafe = ("8.8.8.8", "169.254.2.3", "0.0.0.0", "255.255.255.255",
                  "198.51.100.2", "::ffff:10.1.2.3", "fe80::1",
                  "2001:db8::1", "ff02::1", "fc00::1")
        for value in unsafe:
            with self.subTest(value=value):
                for col in ("declared_lab_literals", "proposed_literals"):
                    obj = packet()
                    obj[col] = [value]
                    result = review_inventory(obj)
                    self.assertEqual(result["status"], "HOLD")
                    self.assertNoAuthority(result)

    def test_strict_canonical_ipv6_identity_prevents_aliases(self):
        for value in ("FD00::1", "fd00:0:0:0:0:0:0:1", "fd00:0000::1",
                      "127.000.0.1", "10.01.2.3", "::FFFF:10.1.2.3"):
            with self.subTest(value=value):
                self.assertEqual(review_inventory(packet([value], [value]))["status"], "HOLD")

    def test_lexical_host_authority_constructions_hold(self):
        for value in ("http://10.1.2.3", "10.1.2.3:80", "[fd00::1]",
                      "10.1.2.3/8", "fd00::1%eth0", "localhost",
                      "10.1.2.3\n", "10.1.2.3\x00", "10.1.2.3@public.example"):
            self.assertEqual(review_inventory(packet([value], [value]))["status"], "HOLD")

    def test_document_schema_is_exact_with_no_extra_authorizing_metadata(self):
        for added in ({"permit_issued": True}, {"owner": "test-owner"},
                      {"authorization_reference": "FAKE"}):
            doc = packet()
            doc.update(added)
            self.assertEqual(review_inventory(doc)["reason"], "INVALID_MANIFEST_SHAPE")

    def test_schema_version_bool_float_string_and_extra_root_denied(self):
        for value in (True, 1.0, "1", None, 0, 2):
            doc = packet()
            doc["schema_version"] = value
            self.assertEqual(review_inventory(doc)["status"], "HOLD")

    def test_input_types_and_polymorphic_literals_fail_closed(self):
        class StringSubclass(str):
            pass
        for value in (123, True, None, b"10.1.2.3", StringSubclass("10.1.2.3"),
                      ["10.1.2.3"], {"value": "10.1.2.3"}):
            doc = packet()
            doc["proposed_literals"] = [value]
            self.assertEqual(review_inventory(doc)["status"], "HOLD")

    def test_malformed_collections_are_held(self):
        for bad in (None, (), set(), {}, 123, "10.1.2.3", [True],
                    ["10.1.2.3"] * 33):
            with self.subTest(type=type(bad).__name__):
                self.assertEqual(review_inventory(packet(proposed=bad))["status"], "HOLD")

    def test_top_level_object_shape_is_exact(self):
        for obj in ([], None, 1, True, "test", {"schema_version": 1}, {}):
            self.assertEqual(review_inventory(obj)["status"], "HOLD")

    def test_duplicate_json_keys_are_rejected_before_shape_check(self):
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":1,"declared_lab_literals":[],"declared_lab_literals":[]}',
            b'{"x":{"a":1,"a":2}}',
        ):
            with self.assertRaises(ValueError):
                parse_document(raw)

    def test_nonfinite_and_overly_nested_json_fail_closed(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
                    b"[" * 2000 + b"0" + b"]" * 2000):
            try:
                parsed = parse_document(raw)
            except ValueError:
                continue
            self.assertEqual(review_inventory(parsed)["status"], "HOLD")

    def test_non_ascii_oversize_and_nonbytes_rejected(self):
        for raw in (b"", b"\xff\xfe", b"x" * (MAX_MANIFEST_BYTES + 1),
                    "{}", bytearray(b"{}"), None, True):
            with self.assertRaises(ValueError):
                parse_document(raw)

    def test_no_socket_dns_or_lightup_runtime_dependency(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network opened")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS called")):
                self.assertNoAuthority(review_inventory(packet()))
                self.assertNoAuthority(review_inventory(packet(proposed=["8.8.8.8"])))

    def _cli(self, raw, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=raw, capture_output=True, timeout=5, check=False)

    def test_cli_review_only_has_nonzero_exit_three(self):
        raw = json.dumps(packet()).encode("ascii")
        result = self._cli(raw)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "REVIEW_ONLY")
        self.assertNoAuthority(json.loads(result.stdout))

    def test_cli_held_result_and_argument_denials_exit_two(self):
        for raw, args in ((b'{"not_a_manifest":true}', ()), (b"", ("--allow",)),
                          (b"\xff", ())):
            with self.subTest(raw=raw, args=args):
                result = self._cli(raw, *args)
                self.assertEqual(result.returncode, 2)
                self.assertNoAuthority(json.loads(result.stdout))

    def test_cli_input_privacy_and_size_limit(self):
        private = b"PRIVATE_ASSET_CANARY"
        result = self._cli(private + b"x" * 8192)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(private, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["reason"], "INVALID_MANIFEST_JSON")

    def test_cli_shell_chain_never_promotes_shape_check(self):
        canary = b"THIS_IS_NOT_AN_AUTHORIZATION"
        command = [ "sh", "-c",
                    f"{sys.executable} {SCRIPT} && echo {canary.decode('ascii')}" ]
        process = subprocess.run(command, input=json.dumps(packet()).encode("ascii"),
                                 capture_output=True, timeout=5, check=False)
        self.assertEqual(process.returncode, 3)
        self.assertNotIn(canary, process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
