"""Post-copy bounded snapshots withstand an input change at the first len check.

This deterministic simulated caller-side race intercepts the review module's
first len(raw). It does not use network, threads, execution or real permission.
It verifies that validation applies to the immutable COPY, not only the
caller-owned mutable container measured before that copy existed.
"""
from __future__ import annotations

import builtins
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import lightup.scope_collection_snapshot_review_294 as reviewmod

_F = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "scan_approved", "merge_approved", "release_approved",
)


class SnapshotCopyLimitTests(unittest.TestCase):
    def assert_hold_no_authority(self, receipt):
        self.assertEqual(receipt.status, "HOLD")
        self.assertFalse(bool(receipt))
        self.assertEqual(receipt._hosts, frozenset())
        self.assertEqual(receipt._networks, ())
        public = receipt.to_public_dict()
        self.assertEqual(public["status"], "HOLD")
        for field in _F:
            self.assertIs(public[field], False)
            self.assertIs(getattr(receipt, field), False)

    def _mutate_after_length_observation(self, source, additions):
        observed = []
        def vulnerable_len(value):
            if value is source:
                # The caller's list grows *after* the original len check
                # measured it, but *before* the review copies its contents.
                source.extend(additions)
                observed.append("original_size_reported")
                return 1
            return builtins.len(value)
        with patch.object(reviewmod, "len", vulnerable_len, create=True):
            result = reviewmod.snapshot_untrusted_scope_collections(
                source if isinstance(source[0], str) and source[0].endswith(".test") else [],
                source if isinstance(source[0], str) and source[0].endswith("/32") else [],
            )
        self.assertEqual(observed, ["original_size_reported"])
        return result

    def test_host_list_growth_past_max_after_precheck_is_hold(self):
        hosts = ["base.example.test"]
        additional = [f"added-{i}.example.test" for i in range(128)]
        result = self._mutate_after_length_observation(hosts, additional)
        self.assertEqual(len(hosts), 129)
        self.assert_hold_no_authority(result)

    def test_network_list_growth_past_max_after_precheck_is_hold(self):
        networks = ["8.8.8.0/32"]
        additional = [f"8.8.8.{i}/32" for i in range(1, 129)]
        result = self._mutate_after_length_observation(networks, additional)
        self.assertEqual(len(networks), 129)
        self.assert_hold_no_authority(result)

    def test_128_unique_hosts_still_review_only_without_external_mutation(self):
        values = [f"host-{i}.example.test" for i in range(128)]
        receipt = reviewmod.snapshot_untrusted_scope_collections(values, [])
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertFalse(bool(receipt))
        self.assertEqual(len(receipt._hosts), 128)

    def test_128_unique_ipv4_cidrs_still_review_only_without_external_mutation(self):
        values = [f"8.8.8.{i}/32" for i in range(128)]
        receipt = reviewmod.snapshot_untrusted_scope_collections([], values)
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertFalse(bool(receipt))
        self.assertEqual(len(receipt._networks), 128)

    def test_129_unique_hosts_and_networks_are_hold_normally(self):
        hosts = [f"host-{i}.example.test" for i in range(129)]
        networks = [f"8.8.8.{i}/32" for i in range(129)]
        self.assert_hold_no_authority(
            reviewmod.snapshot_untrusted_scope_collections(hosts, ())
        )
        self.assert_hold_no_authority(
            reviewmod.snapshot_untrusted_scope_collections((), networks)
        )

    def test_offline_snapshot_limit_checks_do_not_use_dns_or_subprocess(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")):
            hosts = [f"host-{i}.example.test" for i in range(129)]
            self.assert_hold_no_authority(
                reviewmod.snapshot_untrusted_scope_collections(hosts, ())
            )


if __name__ == "__main__":
    unittest.main()
