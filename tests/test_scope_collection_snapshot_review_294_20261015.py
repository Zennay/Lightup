"""Opt-in, non-authorizing collection-snapshot review acceptance for #294.

These tests complement (never replace) the expected RED *installed* canaries
in test_scope_294_current_main_mutable_alias_red_20261015.py.
"""
from __future__ import annotations

import os
import sys
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.scope import ScopePolicy
from lightup.scope_collection_snapshot_review_294 import (
    ScopeCollectionReview, inspect_existing_scope_policy,
    snapshot_untrusted_scope_collections,
)

FALSE_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


class ScopeCollectionSnapshotReferenceTests(unittest.TestCase):
    def _assert_no_authority(self, receipt):
        self.assertIs(bool(receipt), False)
        public = receipt.to_public_dict()
        self.assertEqual(set(public), {"status", "reason", *FALSE_FLAGS})
        for name in FALSE_FLAGS:
            self.assertIs(getattr(receipt, name), False)
            self.assertIs(public[name], False)

    def test_mutable_set_list_copy_is_detached_and_never_authorizing(self):
        hosts = {"fixture.example.test"}
        networks = ["8.8.8.0/24"]
        receipt = snapshot_untrusted_scope_collections(hosts, networks)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertEqual(receipt.reason, "canonical_collections")
        self._assert_no_authority(receipt)
        hosts.add("unapproved.example.test")
        networks.append("1.1.1.0/24")
        self.assertEqual(receipt._hosts, frozenset({"fixture.example.test"}))
        self.assertEqual(receipt._networks, ("8.8.8.0/24",))

    def test_mutable_list_removal_does_not_change_review(self):
        hosts = ["fixture.example.test", "other.example.test"]
        networks = ["8.8.8.0/24", "1.1.1.0/24"]
        receipt = snapshot_untrusted_scope_collections(hosts, networks)
        hosts.clear()
        networks.clear()
        self.assertEqual(len(receipt._hosts), 2)
        self.assertEqual(len(receipt._networks), 2)
        self._assert_no_authority(receipt)

    def test_immutable_frozenset_tuple_shape_is_review_only(self):
        hosts = frozenset({"fixture.example.test"})
        networks = ("8.8.8.0/24", "2606:4700:4700::/48")
        receipt = snapshot_untrusted_scope_collections(hosts, networks)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertEqual(receipt._hosts, hosts)
        self.assertEqual(receipt._networks, networks)
        self._assert_no_authority(receipt)

    def test_empty_collections_are_still_never_permissions(self):
        receipt = snapshot_untrusted_scope_collections(set(), list())
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self._assert_no_authority(receipt)

    def test_invalid_container_types_fail_closed_without_invoking_iter(self):
        class Malicious:
            def __iter__(self):
                raise AssertionError("hostile __iter__ called")
            def __len__(self):
                raise AssertionError("hostile __len__ called")
        for raw in (Malicious(), None, "fixture.example.test", {"bad": "value"}, 1):
            with self.subTest(kind=type(raw).__name__):
                for receipt in (
                    snapshot_untrusted_scope_collections(raw, ()),
                    snapshot_untrusted_scope_collections((), raw),
                ):
                    self.assertEqual(receipt.status, "HOLD")
                    self.assertEqual(receipt.reason, "invalid_collections")
                    self._assert_no_authority(receipt)

    def test_container_subclasses_and_string_subclasses_fail_closed(self):
        class HostList(list):
            pass
        class NetworkTuple(tuple):
            pass
        class SuspiciousStr(str):
            def __str__(self):
                raise AssertionError("str coercion forbidden")
        cases = (
            (HostList(["fixture.example.test"]), ()),
            (["fixture.example.test"], NetworkTuple(("8.8.8.0/24",))),
            ([SuspiciousStr("fixture.example.test")], ()),
            ((), [SuspiciousStr("8.8.8.0/24")]),
        )
        for hosts, networks in cases:
            with self.subTest(hosts=type(hosts).__name__, networks=type(networks).__name__):
                receipt = snapshot_untrusted_scope_collections(hosts, networks)
                self.assertEqual(receipt.status, "HOLD")
                self._assert_no_authority(receipt)

    def test_128_boundary_and_129_refusal_are_deterministic(self):
        hosts = [f"host-{i}.example.test" for i in range(128)]
        networks = [f"8.8.8.{i}/32" for i in range(128)]
        self.assertEqual(snapshot_untrusted_scope_collections(hosts, networks).status, "REVIEW_ONLY")
        for collection in (
            snapshot_untrusted_scope_collections(hosts + ["extra.example.test"], networks),
            snapshot_untrusted_scope_collections(hosts, networks + ["1.1.1.0/24"]),
        ):
            self.assertEqual(collection.status, "HOLD")
            self._assert_no_authority(collection)

    def test_invalid_host_controls_and_oversized_names_fail_closed(self):
        for bad in ("", "a" * 254, "bad\x00.example.test", "bad\n.example.test"):
            with self.subTest(label=repr(bad)[:35]):
                receipt = snapshot_untrusted_scope_collections({bad}, ())
                self.assertEqual(receipt.status, "HOLD")
                self._assert_no_authority(receipt)

    def test_malformed_and_oversized_cidrs_fail_closed(self):
        for bad in ("", "not-a-network", "8.8.8.8/99", "x" * 65):
            with self.subTest(cidr=bad[:20]):
                receipt = snapshot_untrusted_scope_collections((), [bad])
                self.assertEqual(receipt.status, "HOLD")
                self._assert_no_authority(receipt)

    def test_ordinary_exact_installed_policy_is_shape_review_only(self):
        policy = ScopePolicy(
            allow_private_lab=False,
            explicit_hosts=frozenset({"fixture.example.test"}),
            explicit_networks=("8.8.8.0/24",),
            require_authorization_for_public=True,
        )
        receipt = inspect_existing_scope_policy(policy)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self._assert_no_authority(receipt)

    def test_installed_policy_with_mutable_set_or_list_is_hold(self):
        examples = (
            ScopePolicy(explicit_hosts={"fixture.example.test"}),
            ScopePolicy(explicit_networks=["8.8.8.0/24"]),
        )
        for policy in examples:
            with self.subTest(kind=type(policy.explicit_hosts).__name__):
                receipt = inspect_existing_scope_policy(policy)
                self.assertEqual(receipt.status, "HOLD")
                self.assertEqual(receipt.reason, "invalid_policy")
                self._assert_no_authority(receipt)

    def test_forged_policy_and_type_confused_switches_are_hold(self):
        class PretendPolicy:
            explicit_hosts = frozenset()
            explicit_networks = ()
            allow_private_lab = False
            require_authorization_for_public = True
        policies = (
            PretendPolicy(),
            ScopePolicy(allow_private_lab="false"),
            ScopePolicy(require_authorization_for_public=1),
        )
        for policy in policies:
            with self.subTest(name=type(policy).__name__):
                receipt = inspect_existing_scope_policy(policy)
                self.assertEqual(receipt.status, "HOLD")
                self._assert_no_authority(receipt)

    def test_receipt_has_no_settable_authority_and_public_data_is_minimal(self):
        receipt = snapshot_untrusted_scope_collections({"secret.example.test"}, ["8.8.8.0/24"])
        # CPython 3.11 may raise TypeError from frozen+slots __setattr__;
        # 3.14 raises FrozenInstanceError/AttributeError. In every case,
        # separately assert that neither private data nor authority changed.
        original_hosts = receipt._hosts
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            receipt.permit_issued = True
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            receipt._hosts = frozenset({"different.example.test"})
        self.assertIs(receipt.permit_issued, False)
        self.assertIs(receipt._hosts, original_hosts)
        public = receipt.to_public_dict()
        self.assertNotIn("secret.example.test", repr(receipt))
        self.assertNotIn("secret.example.test", repr(public))
        self.assertNotIn("8.8.8.0/24", repr(public))
        self._assert_no_authority(receipt)

    def test_forged_receipt_labels_normalize_to_opaque_hold(self):
        malicious = ScopeCollectionReview("PERMIT", "approved")
        public = malicious.to_public_dict()
        self.assertEqual(public["status"], "HOLD")
        self.assertEqual(public["reason"], "invalid_receipt")
        self._assert_no_authority(malicious)
        strange = ScopeCollectionReview("REVIEW_ONLY", object())
        self.assertEqual(strange.to_public_dict()["status"], "HOLD")

    def test_real_snapshot_and_inspection_never_launch_process_or_network(self):
        with patch("socket.socket", side_effect=AssertionError("socket invoked")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS invoked")), \
             patch("subprocess.Popen", side_effect=AssertionError("process invoked")):
            r1 = snapshot_untrusted_scope_collections({"fixture.example.test"}, ["8.8.8.0/24"])
            r2 = inspect_existing_scope_policy(
                ScopePolicy(explicit_hosts=frozenset(), explicit_networks=())
            )
        self.assertEqual(r1.status, "REVIEW_ONLY")
        self.assertEqual(r2.status, "REVIEW_ONLY")
        self._assert_no_authority(r1)
        self._assert_no_authority(r2)


if __name__ == "__main__":
    unittest.main()
