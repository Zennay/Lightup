"""Issue #294/#296: exact spelling-only network review, not policy authority.

Test the *opt-in* review component independently of source-owned ScopePolicy.
Every value is synthetic text; no network traffic, grants, handlers or scans.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from lightup.scope import ScopePolicy
from lightup.scope_collection_snapshot_review_294 import (
    inspect_existing_scope_policy,
    snapshot_untrusted_scope_collections,
)
from scope_294_collection_review_cli import review_private_manifest


class ExactCIDRReviewTests(unittest.TestCase):
    def assert_hold(self, review):
        self.assertIs(type(review.status), str)
        self.assertEqual(review.status, "HOLD")
        self.assertFalse(bool(review))
        info = review.to_public_dict()
        self.assertEqual(info["status"], "HOLD")
        self.assertFalse(any(v is not False for k, v in info.items()
                             if k not in ("status", "reason")))
        self.assertNotIn("8.8.8", str(info))
        self.assertNotIn("2606:4700", str(info))

    def assert_review_not_permission(self, review):
        self.assertEqual(review.status, "REVIEW_ONLY")
        self.assertFalse(bool(review))
        info = review.to_public_dict()
        self.assertEqual(info["status"], "REVIEW_ONLY")
        self.assertFalse(any(v is not False for k, v in info.items()
                             if k not in ("status", "reason")))

    def test_exact_public_ipv4_ipv6_networks_only_review(self):
        examples = (
            "8.8.8.0/24",
            "1.1.1.0/24",
            "8.8.8.8/32",
            "2606:4700:4700::/48",
            "2001:4860::/32",
            "2606:4700:4700::8888/128",
        )
        for item in examples:
            with self.subTest(cidr=item):
                review = snapshot_untrusted_scope_collections([], [item])
                self.assert_review_not_permission(review)
                self.assertEqual(review._networks, (item,))

    def test_host_bit_ipv4_must_not_expand_into_authorizing_network(self):
        for entry in ("8.8.8.8/24", "8.8.8.7/29", "1.1.1.1/24"):
            with self.subTest(entry=entry):
                self.assert_hold(snapshot_untrusted_scope_collections([], [entry]))

    def test_host_bit_ipv6_must_not_expand(self):
        for entry in ("2606:4700:4700::1/48", "2001:4860::1/32"):
            with self.subTest(entry=entry):
                self.assert_hold(snapshot_untrusted_scope_collections([], [entry]))

    def test_bare_address_cannot_be_turned_into_implicit_single_host_cidr(self):
        for entry in ("8.8.8.8", "2606:4700:4700::8888", "1.1.1.1"):
            with self.subTest(entry=entry):
                self.assert_hold(snapshot_untrusted_scope_collections([], [entry]))

    def test_noncanonical_network_spelling_is_not_normalized_silently(self):
        for entry in (
            "8.8.8.0/024", "8.8.8.0/255.255.255.0",
            "2606:4700:4700:0:0:0:0:0/48",
            "2606:4700:4700::/048",
            "2001:0db8::/32",
        ):
            with self.subTest(entry=entry):
                self.assert_hold(snapshot_untrusted_scope_collections([], [entry]))

    def test_nonstring_minting_values_are_denied_before_parser(self):
        values = (
            134744072, True, False,
            b"\x08\x08\x08\x08",
            bytearray(b"\x08\x08\x08\x08"),
            None,
        )
        for value in values:
            with self.subTest(kind=type(value).__name__):
                self.assert_hold(snapshot_untrusted_scope_collections([], [value]))

    def test_mixed_valid_and_bad_entries_fail_atomically(self):
        valid = "8.8.8.0/24"
        bad = "1.1.1.1/24"
        for entries in ([bad, valid], [valid, bad]):
            with self.subTest(entries=entries):
                self.assert_hold(snapshot_untrusted_scope_collections([], entries))

    def test_caller_mutation_after_valid_review_does_not_change_snapshot(self):
        networks = ["8.8.8.0/24"]
        review = snapshot_untrusted_scope_collections([], networks)
        self.assert_review_not_permission(review)
        networks[0] = "8.8.8.8/24"
        self.assertEqual(review._networks, ("8.8.8.0/24",))
        self.assert_review_not_permission(review)

    def test_inspection_of_legacy_noncanonical_installed_policy_holds(self):
        # The original ScopePolicy allows this lexical alias; the reviewer
        # refuses to call it canonical.  No production policy code is changed.
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_networks=("8.8.8.8/24",),
        )
        self.assert_hold(inspect_existing_scope_policy(policy))

    def test_offline_cli_bare_and_host_bit_cidrs_are_private_hold(self):
        for value in ("8.8.8.8/24", "8.8.8.8", "2606:4700:4700::1/48"):
            with self.subTest(value=value):
                data = json.dumps({"hosts": [], "networks": [value]}).encode()
                receipt = review_private_manifest(data)
                self.assert_hold(receipt)
                self.assertNotIn(value, str(receipt.to_public_dict()))

    def test_exact_valid_cidr_cli_still_returns_review_not_authority(self):
        payload = b'{"hosts":[],"networks":["8.8.8.0/24"]}'
        review = review_private_manifest(payload)
        self.assert_review_not_permission(review)

    def test_review_canary_is_pure_offline(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("subprocess forbidden")):
            self.assert_hold(snapshot_untrusted_scope_collections([], ["8.8.8.8/24"]))
            self.assert_review_not_permission(
                snapshot_untrusted_scope_collections([], ["8.8.8.0/24"])
            )


if __name__ == "__main__":
    unittest.main()
