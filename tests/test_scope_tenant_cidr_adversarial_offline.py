"""Independent stress and adversarial controls for tenant CIDR review-only checks."""
from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path
import random
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_tenant_cidr_disjoint_offline import review_network_inventory
from scripts.check_scope_tenant_cidr_narrowing_offline import review_tenant_narrowing
from scripts.check_scope_tenant_cidr_history_offline import review_tenant_network_history

FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def record(index, cidr, tenant="TENANT"):
    return {"tenant_id": tenant, "scope_id": f"NET{index}", "cidr": cidr}


def snapshot(entries):
    return {"schema_version": 1, "networks": entries}


class TenantCidrAdversarialTests(unittest.TestCase):
    def assertNeverAuthorized(self, receipt):
        self.assertTrue(all(receipt[f] is False for f in FLAGS))
        self.assertEqual(set(receipt), {"schema_version", "status", "reason", *FLAGS})

    def test_exact_sixty_four_disjoint_ipv4_networks_review_only(self):
        document = snapshot([record(i, f"10.20.{i}.0/24") for i in range(64)])
        receipt = review_network_inventory(document)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertNeverAuthorized(receipt)

    def test_exact_sixty_four_disjoint_ipv6_networks_review_only(self):
        document = snapshot([
            record(i, str(ipaddress.ip_network(f"fd00:0:0:{i:x}::/64")))
            for i in range(64)
        ])
        receipt = review_network_inventory(document)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertNeverAuthorized(receipt)

    def test_sixty_five_disjoint_ipv4_networks_fail_closed(self):
        document = snapshot([record(i, f"10.20.{i}.0/24") for i in range(65)])
        receipt = review_network_inventory(document)
        self.assertEqual(receipt["reason"], "INVALID_RECORD_COUNT")
        self.assertNeverAuthorized(receipt)

    def test_last_record_can_conflict_with_first_without_partial_acceptance(self):
        entries = [record(i, f"10.20.{i}.0/24") for i in range(63)]
        entries.append(record(63, "10.20.0.128/25", tenant="OTHER"))
        receipt = review_network_inventory(snapshot(entries))
        self.assertEqual(receipt["reason"], "OVERLAPPING_NETWORKS")
        self.assertNeverAuthorized(receipt)

    def test_random_adjacent_ipv4_and_nested_network_oracle(self):
        rng = random.Random(0xD15C)
        for _ in range(220):
            left, right = rng.sample(range(64), 2)
            first = f"10.77.{left}.0/24"
            other = f"10.77.{right}.0/24"
            valid = review_network_inventory(snapshot([
                record(0, first), record(1, other, tenant="OTHER"),
            ]))
            self.assertEqual(valid["status"], "REVIEW_ONLY")
            conflict = review_network_inventory(snapshot([
                record(0, first),
                record(1, f"10.77.{left}.128/25", tenant="OTHER"),
            ]))
            self.assertEqual(conflict["status"], "HOLD")
            self.assertNeverAuthorized(valid)
            self.assertNeverAuthorized(conflict)

    def test_random_ipv6_subnet_oracle(self):
        rng = random.Random(0xD16C)
        for _ in range(160):
            left, right = rng.sample(range(64), 2)
            first = str(ipaddress.ip_network(f"fd00:0:0:{left:x}::/64"))
            disjoint = str(ipaddress.ip_network(f"fd00:0:0:{right:x}::/64"))
            nested = str(ipaddress.ip_network(f"fd00:0:0:{left:x}:8000::/65"))
            valid = review_network_inventory(snapshot([
                record(0, first), record(1, disjoint, tenant="OTHER"),
            ]))
            overlapping = review_network_inventory(snapshot([
                record(0, first), record(1, nested, tenant="OTHER"),
            ]))
            self.assertEqual(valid["status"], "REVIEW_ONLY")
            self.assertEqual(overlapping["status"], "HOLD")
            self.assertNeverAuthorized(valid)
            self.assertNeverAuthorized(overlapping)

    def test_tenant_identity_does_not_override_address_overlap(self):
        for other_label in ("ALPHA", "BETA", "TENANT", "OTHER-1"):
            receipt = review_network_inventory(snapshot([
                record(1, "172.16.0.0/16", tenant="ALPHA"),
                record(2, "172.16.20.0/24", tenant=other_label),
            ]))
            self.assertEqual(receipt["status"], "HOLD")
            self.assertNeverAuthorized(receipt)

    def test_widened_network_then_reverted_held_across_all_history(self):
        earlier = snapshot([record(1, "10.20.0.0/25")])
        widened = snapshot([record(1, "10.20.0.0/24")])
        history = {"schema_version": 1,
                   "versions": [earlier, widened, copy.deepcopy(earlier)]}
        receipt = review_tenant_network_history(history)
        self.assertEqual(receipt["reason"], "NONMONOTONIC_TENANT_HISTORY")
        self.assertNeverAuthorized(receipt)

    def test_no_tenant_swaps_even_when_both_snapshots_disjoint(self):
        previous = snapshot([record(1, "10.20.0.0/24", tenant="ALPHA")])
        proposed = snapshot([record(1, "10.20.0.0/25", tenant="BETA")])
        receipt = review_tenant_narrowing({
            "schema_version": 1, "previous": previous, "proposed": proposed})
        self.assertEqual(receipt["reason"], "NEW_OR_REASSIGNED_SCOPE")
        self.assertNeverAuthorized(receipt)

    def test_noncanonical_ipv6_textual_aliases_do_not_bypass_overlap(self):
        for bad in ("FD00:0:0:1::/64", "fd00:0:0:0001::/64",
                    "fd00:0:0:1:0:0:0:0/64"):
            receipt = review_network_inventory(snapshot([record(1, bad)]))
            self.assertEqual(receipt["status"], "HOLD")
            self.assertNeverAuthorized(receipt)

    def test_unicode_id_escapes_cannot_mint_valid_tenants(self):
        for id_value in ("T\u200b", "T\u202e", "T\u00a0",
                         "T\n", "T\x00", "Té"):
            receipt = review_network_inventory(snapshot([
                {"tenant_id": id_value, "scope_id": "NET", "cidr": "10.0.0.0/8"}
            ]))
            self.assertEqual(receipt["status"], "HOLD")
            self.assertNeverAuthorized(receipt)

    def test_no_socket_dns_or_mutation_during_large_review(self):
        doc = snapshot([record(i, f"10.33.{i}.0/24") for i in range(64)])
        before = copy.deepcopy(doc)
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                result = review_network_inventory(doc)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(doc, before)
        self.assertNeverAuthorized(result)


if __name__ == "__main__":
    unittest.main()
