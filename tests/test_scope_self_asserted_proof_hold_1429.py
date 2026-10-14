"""Offline and real-subprocess non-authority regressions for #1429."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scope_self_asserted_proof_hold_1429.py"
spec = importlib.util.spec_from_file_location("scope_self_asserted_proof_hold_1429", SCRIPT)
assert spec is not None and spec.loader is not None
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

SHA = "a" * 40
LANES = (
    "hosted_python_311",
    "hosted_python_314",
    "registered_vps",
    "installed_ingress",
)
FLAGS = ("authorized", "permit", "dispatch", "merge", "deploy", "release")


def packet(**overrides):
    item = {
        "schema": review.INPUT_SCHEMA,
        "head": SHA,
        "claims": [{"lane": lane, "head": SHA, "result": "pass"} for lane in LANES],
    }
    item.update(overrides)
    return item


def encoded(item):
    return json.dumps(item, separators=(",", ":")).encode("utf-8")


class SelfAssertedProofHoldTests(unittest.TestCase):
    def check_hold(self, payload, *, coherent=False, passing=0):
        result = review.review_bytes(payload)
        self.assertEqual(result["schema"], review.OUTPUT_SCHEMA)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["input_integrity"], "COHERENT" if coherent else "REJECTED")
        self.assertEqual(result["unverified_self_asserted_pass_claims"], passing)
        self.assertIs(result["verified_evidence"], False)
        for name in FLAGS:
            self.assertIs(result[name], False)
        rendered = json.dumps(result)
        self.assertNotIn(SHA, rendered)
        self.assertNotIn("hosted_python_311", rendered)
        self.assertNotIn("installed_ingress", rendered)
        return result

    def test_complete_all_pass_is_still_hold(self):
        self.check_hold(encoded(packet()), coherent=True, passing=4)

    def test_partial_claimed_pass_is_coherent_but_unverified(self):
        item = packet()
        item["claims"][1]["result"] = "queued"
        item["claims"][2]["result"] = "cancelled"
        self.check_hold(encoded(item), coherent=True, passing=2)

    def test_claim_order_does_not_confer_authority(self):
        item = packet()
        item["claims"].reverse()
        self.check_hold(encoded(item), coherent=True, passing=4)

    def test_mixed_commit_sha_rejected_atomically(self):
        item = packet()
        item["claims"][2]["head"] = "b" * 40
        self.check_hold(encoded(item))

    def test_uppercase_or_short_sha_rejected(self):
        for head in ("A" * 40, "a" * 39, "0x" + SHA, True, 42):
            with self.subTest(head=repr(head)):
                self.check_hold(encoded(packet(head=head)))

    def test_missing_unknown_duplicate_lanes_rejected(self):
        missing = packet()
        missing["claims"].pop()
        unknown = packet()
        unknown["claims"][0]["lane"] = "production_release"
        duplicate = packet()
        duplicate["claims"][1]["lane"] = duplicate["claims"][0]["lane"]
        for value in (missing, unknown, duplicate):
            with self.subTest(value=value):
                self.check_hold(encoded(value))

    def test_noncanonical_value_types_rejected(self):
        values = (
            {"claims": [*packet()["claims"][:3], {"lane": LANES[3], "head": SHA, "result": True}]},
            {"claims": "fake"},
            {"schema": True},
            {"head": ["a"] * 40},
        )
        for edit in values:
            with self.subTest(edit=edit):
                self.check_hold(encoded(packet(**edit)))

    def test_extraneous_authorization_fields_rejected(self):
        value = packet(approved=True, release=True, customer_token="SECRET-SENTINEL")
        self.check_hold(encoded(value))

    def test_duplicate_json_keys_at_any_level_rejected(self):
        raw = encoded(packet()).decode("utf-8")
        at_top = raw.replace('"schema":', '"schema":"forged","schema":', 1)
        nested = raw.replace('"result":', '"result":"pass","result":', 1)
        for case in (at_top, nested):
            with self.subTest(case=case[:40]):
                self.check_hold(case.encode())

    def test_nonfinite_invalid_json_and_utf8_rejected(self):
        for case in (b"NaN", b"Infinity", b"-Infinity", b"{", b"\xff", b"\xef\xbb\xbf" + encoded(packet())):
            with self.subTest(case=case[:30]):
                self.check_hold(case)

    def test_byte_boundary_accepts_bounded_valid_claims(self):
        self.assertLess(len(encoded(packet())), review.MAX_STDIN_BYTES)
        self.check_hold(encoded(packet()), coherent=True, passing=4)
        self.check_hold(b" " * (review.MAX_STDIN_BYTES + 1))

    def test_unknown_nested_shape_and_list_rejected(self):
        item = packet()
        item["claims"][0]["extra"] = "anything"
        self.check_hold(encoded(item))
        self.check_hold(encoded([packet()]))

    def test_no_ambient_network_or_file_reads_from_direct_review(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")), \
             patch("builtins.open", side_effect=AssertionError("file attempted")), \
             patch("subprocess.Popen", side_effect=AssertionError("process attempted")):
            self.check_hold(encoded(packet()), coherent=True, passing=4)

    def cli(self, payload, args=("--stdin-json",)):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_real_cli_success_claims_still_exit_2(self):
        child = self.cli(encoded(packet()))
        self.assertEqual(child.returncode, 2, child.stderr)
        self.assertEqual(child.stderr, b"")
        self.assertEqual(child.stdout.count(b"\n"), 1)
        self.assertEqual(json.loads(child.stdout)["unverified_self_asserted_pass_claims"], 4)
        self.assertEqual(json.loads(child.stdout)["status"], "HOLD")

    def test_real_cli_bad_args_do_not_read_or_echo_stdin(self):
        for args in ((), ("--stdin-json", "--release"), ("--release",), ("--stdin-json", "--stdin-json")):
            with self.subTest(args=args):
                child = self.cli(b"PRIVATE-CREDENTIAL-SENTINEL", args)
                self.assertEqual(child.returncode, 2)
                self.assertNotIn(b"PRIVATE-CREDENTIAL-SENTINEL", child.stdout + child.stderr)
                self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")

    def test_real_cli_overlimit_holds_without_leaking_data(self):
        child = self.cli(b"SECRET-" + b"x" * (review.MAX_STDIN_BYTES + 1))
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(child.stdout)["input_integrity"], "REJECTED")
        self.assertNotIn(b"SECRET", child.stdout + child.stderr)

    def test_real_cli_invalid_utf8_no_traceback(self):
        child = self.cli(b'{"claims":"SECRET-\xff"}')
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        self.assertNotIn(b"SECRET", child.stdout)


if __name__ == "__main__":
    unittest.main()
