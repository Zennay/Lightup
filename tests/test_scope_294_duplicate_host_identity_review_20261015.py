"""Duplicate-host metadata is HOLD, never implicitly widened/deduplicated.

This suite only exercises the uninstalled #294 reviewer and offline JSON CLI.
It neither changes source-owned ScopePolicy nor grants permission to targets.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from lightup.scope_collection_snapshot_review_294 import (
    snapshot_untrusted_scope_collections,
    inspect_existing_scope_policy,
)
from lightup.scope import ScopePolicy
from scope_294_collection_review_cli import review_private_manifest

_SCRIPT = os.path.join(_ROOT, "scripts", "scope_294_collection_review_cli.py")
_PERMISSION_KEYS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


class DuplicateScopeHostIdentityTests(unittest.TestCase):
    def assert_hold_only(self, result):
        self.assertEqual(result.status, "HOLD")
        self.assertIs(bool(result), False)
        data = result.to_public_dict()
        self.assertEqual(data["status"], "HOLD")
        for key in _PERMISSION_KEYS:
            self.assertIs(data[key], False)
        self.assertNotIn("host.example.test", str(data))

    def test_exact_duplicate_host_list_fails_closed(self):
        self.assert_hold_only(snapshot_untrusted_scope_collections(
            ["host.example.test", "host.example.test"], ()
        ))

    def test_exact_duplicate_host_tuple_fails_closed(self):
        self.assert_hold_only(snapshot_untrusted_scope_collections(
            ("host.example.test", "host.example.test"), ()
        ))

    def test_mixed_valid_networks_do_not_rescue_duplicate_hosts(self):
        for hosts in (
            ["host.example.test", "host.example.test"],
            ["other.example.test", "host.example.test", "host.example.test"],
        ):
            with self.subTest(n=len(hosts)):
                self.assert_hold_only(snapshot_untrusted_scope_collections(
                    hosts, ["8.8.8.0/24", "1.1.1.0/24"]
                ))

    def test_exact_container_sets_are_already_unique_and_review_only(self):
        for hosts in (
            {"host.example.test"},
            frozenset({"host.example.test"}),
        ):
            with self.subTest(kind=type(hosts).__name__):
                result = snapshot_untrusted_scope_collections(hosts, ())
                self.assertEqual(result.status, "REVIEW_ONLY")
                self.assertIs(bool(result), False)
                self.assertEqual(result._hosts, frozenset({"host.example.test"}))
                self.assertIs(result.permit_issued, False)

    def test_distinct_declared_host_spellings_not_silently_normalized(self):
        # Alias canonicalization is owned by #285; this review is lexical only.
        names = ["host.example.test", "HOST.EXAMPLE.TEST"]
        result = snapshot_untrusted_scope_collections(names, ())
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result._hosts, frozenset(names))
        self.assertIs(bool(result), False)

    def test_original_caller_mutation_after_review_isolated(self):
        names = ["host.example.test"]
        result = snapshot_untrusted_scope_collections(names, ())
        self.assertEqual(result.status, "REVIEW_ONLY")
        names.append("host.example.test")
        self.assertEqual(result._hosts, frozenset({"host.example.test"}))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertIs(bool(result), False)

    def test_exact_policy_containers_not_modified(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"host.example.test"}),
            explicit_networks=("8.8.8.0/24",),
        )
        original_hosts = policy.explicit_hosts
        receipt = inspect_existing_scope_policy(policy)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertIs(receipt.authorization_verified, False)
        self.assertIs(policy.explicit_hosts, original_hosts)

    def test_json_duplicate_array_elements_are_hold_without_identity_leak(self):
        payload = b'{"hosts":["host.example.test","host.example.test"],"networks":[]}'
        result = review_private_manifest(payload)
        self.assert_hold_only(result)
        child = subprocess.run(
            [sys.executable, "-B", _SCRIPT],
            input=payload,
            capture_output=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(child.returncode, 2)
        self.assertEqual(child.stderr, b"")
        output = json.loads(child.stdout)
        self.assertEqual(output["status"], "HOLD")
        self.assertNotIn("host.example.test", str(output))
        for key in _PERMISSION_KEYS:
            self.assertIs(output[key], False)

    def test_duplicate_review_uses_no_network_or_external_dispatch(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            receipt = snapshot_untrusted_scope_collections(
                ["host.example.test", "host.example.test"], ()
            )
        self.assert_hold_only(receipt)


if __name__ == "__main__":
    unittest.main()
