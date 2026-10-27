"""Duplicate network declarations are REVIEW metadata errors, never permits.

Separate from #290 installed ScopePolicy CIDR union semantics. No installed
scope source, network traffic, grant or actual authorization is changed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

BASE = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(BASE, "src"))
sys.path.insert(0, os.path.join(BASE, "scripts"))
from lightup.scope import ScopePolicy
from lightup.scope_collection_snapshot_review_294 import (
    inspect_existing_scope_policy, snapshot_untrusted_scope_collections,
)
from scope_294_collection_review_cli import review_private_manifest

CLI = os.path.join(BASE, "scripts", "scope_294_collection_review_cli.py")
_AUTH_FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


class DuplicateCidrReviewTests(unittest.TestCase):
    def assert_receipt(self, receipt, status):
        self.assertEqual(receipt.status, status)
        self.assertIs(bool(receipt), False)
        d = receipt.to_public_dict()
        self.assertEqual(set(d), {"status", "reason", *_AUTH_FIELDS})
        self.assertEqual(d["status"], status)
        self.assertNotIn("8.8.8", str(d))
        self.assertNotIn("2606:4700", str(d))
        for field in _AUTH_FIELDS:
            self.assertIs(d[field], False)
            self.assertIs(getattr(receipt, field), False)

    def test_two_identical_ipv4_cidrs_are_hold_not_deduplicated(self):
        receipt = snapshot_untrusted_scope_collections(
            [], ["8.8.8.0/24", "8.8.8.0/24"]
        )
        self.assert_receipt(receipt, "HOLD")
        self.assertEqual(receipt._networks, ())

    def test_duplicate_ipv6_cidrs_hold(self):
        receipt = snapshot_untrusted_scope_collections(
            [], ("2606:4700:4700::/48", "2606:4700:4700::/48")
        )
        self.assert_receipt(receipt, "HOLD")

    def test_duplicate_entry_after_valid_hosts_is_atomic_hold(self):
        receipt = snapshot_untrusted_scope_collections(
            {"fixture.example.test"}, ["8.8.8.0/24", "8.8.8.0/24"]
        )
        self.assert_receipt(receipt, "HOLD")
        self.assertEqual(receipt._hosts, frozenset())
        self.assertEqual(receipt._networks, ())

    def test_distinct_networks_preserve_order_and_never_grant(self):
        for pair in (
            ["8.8.8.0/24", "1.1.1.0/24"],
            ["1.1.1.0/24", "8.8.8.0/24"],
        ):
            with self.subTest(pair=pair):
                receipt = snapshot_untrusted_scope_collections([], pair)
                self.assert_receipt(receipt, "REVIEW_ONLY")
                self.assertEqual(receipt._networks, tuple(pair))

    def test_overlap_is_not_silently_merged_in_metadata_layer(self):
        networks = ("8.8.8.0/24", "8.8.8.0/25")
        receipt = snapshot_untrusted_scope_collections([], networks)
        self.assert_receipt(receipt, "REVIEW_ONLY")
        self.assertEqual(receipt._networks, networks)
        # This is only lexical metadata, not ScopePolicy network membership.

    def test_original_network_list_mutation_does_not_change_detached_copy(self):
        entries = ["8.8.8.0/24"]
        receipt = snapshot_untrusted_scope_collections([], entries)
        self.assert_receipt(receipt, "REVIEW_ONLY")
        entries.append("8.8.8.0/24")
        self.assertEqual(receipt._networks, ("8.8.8.0/24",))
        self.assert_receipt(receipt, "REVIEW_ONLY")

    def test_128_distinct_cidrs_still_review_only(self):
        entries = [f"8.8.8.{i}/32" for i in range(128)]
        receipt = snapshot_untrusted_scope_collections([], entries)
        self.assert_receipt(receipt, "REVIEW_ONLY")
        self.assertEqual(receipt._networks, tuple(entries))

    def test_existing_mutable_and_duplicate_policy_is_only_diagnosed(self):
        policy = ScopePolicy(explicit_networks=("8.8.8.0/24", "8.8.8.0/24"))
        old = policy.explicit_networks
        receipt = inspect_existing_scope_policy(policy)
        self.assert_receipt(receipt, "HOLD")
        self.assertIs(policy.explicit_networks, old)

    def test_private_json_cli_duplicate_cidr_holds_with_nonzero_exit(self):
        payload = json.dumps({
            "hosts": ["fixture.example.test"],
            "networks": ["8.8.8.0/24", "8.8.8.0/24"],
        }).encode()
        self.assert_receipt(review_private_manifest(payload), "HOLD")
        child = subprocess.run(
            [sys.executable, "-B", CLI],
            input=payload, capture_output=True, check=False, timeout=15,
        )
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        output = json.loads(child.stdout)
        self.assertEqual(output["status"], "HOLD")
        self.assertNotIn(b"8.8.8", child.stdout)
        self.assertNotIn(b"fixture.example.test", child.stdout)
        for field in _AUTH_FIELDS:
            self.assertIs(output[field], False)

    def test_review_has_no_dns_socket_or_dispatch(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS")), \
             patch("socket.socket", side_effect=AssertionError("socket")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            refused = snapshot_untrusted_scope_collections(
                [], ["8.8.8.0/24", "8.8.8.0/24"]
            )
            accepted = snapshot_untrusted_scope_collections(
                [], ["8.8.8.0/24", "1.1.1.0/24"]
            )
        self.assert_receipt(refused, "HOLD")
        self.assert_receipt(accepted, "REVIEW_ONLY")


if __name__ == "__main__":
    unittest.main()
