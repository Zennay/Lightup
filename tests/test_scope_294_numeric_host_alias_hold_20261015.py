"""Reject numeric IP-alias-looking host metadata without granting authority.

Review-only acceptance: the real ScopePolicy, URL stack and destination binding
remain separate worker-owned boundaries. No external address is contacted.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from lightup.scope import ScopePolicy
from lightup.scope_collection_snapshot_review_294 import (
    snapshot_untrusted_scope_collections, inspect_existing_scope_policy,
)
from scope_294_collection_review_cli import review_private_manifest

SCRIPT = os.path.join(ROOT, "scripts", "scope_294_collection_review_cli.py")
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


class HostNumericAliasHoldTests(unittest.TestCase):
    def assert_no_permission(self, receipt, status):
        self.assertEqual(receipt.status, status)
        self.assertFalse(bool(receipt))
        public = receipt.to_public_dict()
        self.assertEqual(public["status"], status)
        self.assertEqual(set(public), {"status", "reason", *_FLAGS})
        for field in _FLAGS:
            self.assertIs(getattr(receipt, field), False)
            self.assertIs(public[field], False)
        self.assertNotIn("127", repr(public))
        self.assertNotIn("0x7f", repr(public))

    def test_canonical_ipv4_is_not_a_dns_host_metadata_entry(self):
        for name in ("127.0.0.1", "8.8.8.8", "10.0.0.1", "0.0.0.0"):
            with self.subTest(name=name):
                self.assert_no_permission(
                    snapshot_untrusted_scope_collections([name], []), "HOLD"
                )

    def test_shorthand_numeric_hosts_are_not_accepted(self):
        for name in ("127.1", "2130706433", "127.0.1", "0177.0.0.1"):
            with self.subTest(name=name):
                self.assert_no_permission(
                    snapshot_untrusted_scope_collections((name,), ()), "HOLD"
                )

    def test_hex_numeric_forms_are_rejected_before_any_parser(self):
        for name in ("0x7f000001", "0X7F000001", "0x7f.1", "0x7f.0x0.0.1"):
            with self.subTest(name=name):
                self.assert_no_permission(
                    snapshot_untrusted_scope_collections((name,), ()), "HOLD"
                )

    def test_ambiguous_numeric_labels_that_are_not_valid_ipv4_still_hold(self):
        for name in ("999.999.999.999", "08.08.08.08", "1.2.3", "1"):
            with self.subTest(name=name):
                self.assert_no_permission(
                    snapshot_untrusted_scope_collections((name,), ()), "HOLD"
                )

    def test_genuine_dns_names_containing_digits_survive_unmodified(self):
        for name in (
            "127.example.test",
            "1.example.test",
            "ip4-127.example.test",
            "v2.example.test",
            "8.8.8.8.example.test",
            "fixture.example.test",
        ):
            with self.subTest(name=name):
                receipt = snapshot_untrusted_scope_collections([name], [])
                self.assert_no_permission(receipt, "REVIEW_ONLY")
                self.assertEqual(receipt._hosts, frozenset({name}))

    def test_mixed_valid_dns_and_ip_alias_is_atomic_hold(self):
        for names in (
            ["fixture.example.test", "127.1"],
            ["0x7f000001", "fixture.example.test"],
        ):
            receipt = snapshot_untrusted_scope_collections(names, ["8.8.8.0/24"])
            self.assert_no_permission(receipt, "HOLD")
            self.assertEqual(receipt._hosts, frozenset())
            self.assertEqual(receipt._networks, ())

    def test_network_cidr_field_preserves_exact_network_review_only(self):
        receipt = snapshot_untrusted_scope_collections([], ["127.0.0.1/32"])
        self.assert_no_permission(receipt, "REVIEW_ONLY")
        self.assertEqual(receipt._networks, ("127.0.0.1/32",))
        # A syntactically canonical metadata field is not a valid grant;
        # special-use IPs are source-owner #1422 / permit-chain concerns.

    def test_installed_policy_with_ip_alias_is_diagnosed_not_mutated(self):
        hosts = frozenset({"127.1"})
        policy = ScopePolicy(
            explicit_hosts=hosts, explicit_networks=(),
            allow_private_lab=False,
        )
        receipt = inspect_existing_scope_policy(policy)
        self.assert_no_permission(receipt, "HOLD")
        self.assertIs(policy.explicit_hosts, hosts)

    def test_cli_subprocess_returns_nonzero_and_no_identity_leak(self):
        payload = json.dumps(
            {"hosts": ["0x7f000001"], "networks": ["8.8.8.0/24"]}
        ).encode("utf-8")
        receipt = review_private_manifest(payload)
        self.assert_no_permission(receipt, "HOLD")
        child = subprocess.run(
            [sys.executable, "-B", SCRIPT],
            input=payload, capture_output=True, timeout=15, check=False,
        )
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        self.assertEqual(json.loads(child.stdout)["status"], "HOLD")
        self.assertNotIn(b"0x7f000001", child.stdout)
        self.assertNotIn(b"8.8.8", child.stdout)

    def test_review_only_path_does_not_create_socket_or_subprocess(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("dns")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            invalid = snapshot_untrusted_scope_collections(["127.1"], [])
            valid = snapshot_untrusted_scope_collections(["127.example.test"], [])
        self.assert_no_permission(invalid, "HOLD")
        self.assert_no_permission(valid, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
