"""Synthetic test suite for non-authorizing cross-tenant CIDR collisions."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_tenant_cidr_disjoint_offline import (
    MAX_BYTES, MAX_RECORDS, parse_json, review_network_inventory,
)

SCRIPT = ROOT / "scripts" / "check_scope_tenant_cidr_disjoint_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def row(tenant: str, scope: str, cidr: str) -> dict[str, str]:
    return {"tenant_id": tenant, "scope_id": scope, "cidr": cidr}


def inventory(*entries):
    return {"schema_version": 1, "networks": list(entries)}


class DisjointTenantCidrTests(unittest.TestCase):
    def assertNoAuthority(self, result):
        self.assertEqual(
            set(result), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(result[f] is False for f in FLAGS))
        self.assertNotIn("10.0.0.0", json.dumps(result))
        self.assertNotIn("TENANT", json.dumps(result))

    def assertHeld(self, doc, reason=None):
        receipt = review_network_inventory(doc)
        self.assertEqual(receipt["status"], "HOLD", receipt)
        if reason is not None:
            self.assertEqual(receipt["reason"], reason)
        self.assertNoAuthority(receipt)

    def test_separate_tenants_disjoint_ipv4_ipv6_shapes_only(self):
        receipt = review_network_inventory(inventory(
            row("TENANT_A", "NET1", "10.0.0.0/24"),
            row("TENANT_B", "NET2", "10.0.1.0/24"),
            row("TENANT_A", "NET3", "fd00::/64"),
            row("TENANT_B", "NET4", "fd01::/64"),
        ))
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertNoAuthority(receipt)

    def test_single_declared_network_is_only_review(self):
        result = review_network_inventory(inventory(row("A", "A1", "10.10.10.10/32")))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_adjacent_boundary_networks_do_not_overlap(self):
        doc = inventory(row("A", "ONE", "192.168.0.0/25"),
                        row("B", "TWO", "192.168.0.128/25"))
        self.assertEqual(review_network_inventory(doc)["status"], "REVIEW_ONLY")

    def test_exact_cross_tenant_duplicate_network_is_hold(self):
        self.assertHeld(inventory(row("A", "NET1", "10.0.0.0/24"),
                                  row("B", "NET2", "10.0.0.0/24")),
                        "OVERLAPPING_NETWORKS")

    def test_parent_child_cross_tenant_overlap_is_hold(self):
        self.assertHeld(inventory(row("A", "PARENT", "10.0.0.0/8"),
                                  row("B", "CHILD", "10.1.2.0/24")),
                        "OVERLAPPING_NETWORKS")

    def test_reverse_parent_child_order_is_hold(self):
        self.assertHeld(inventory(row("B", "CHILD", "172.20.5.0/24"),
                                  row("A", "PARENT", "172.16.0.0/12")),
                        "OVERLAPPING_NETWORKS")

    def test_same_tenant_overlap_also_holds(self):
        self.assertHeld(inventory(row("A", "NET1", "192.168.0.0/16"),
                                  row("A", "NET2", "192.168.1.0/24")),
                        "OVERLAPPING_NETWORKS")

    def test_ipv6_ula_parent_child_overlap_holds(self):
        self.assertHeld(inventory(row("A", "V6P", "fd00::/8"),
                                  row("B", "V6C", "fd44::/48")),
                        "OVERLAPPING_NETWORKS")

    def test_ipv4_and_ipv6_cannot_overlap(self):
        doc = inventory(row("A", "NET1", "10.0.0.0/8"),
                        row("B", "NET2", "fd00::/8"))
        self.assertEqual(review_network_inventory(doc)["status"], "REVIEW_ONLY")

    def test_duplicate_scope_within_one_tenant_holds(self):
        self.assertHeld(inventory(row("A", "NET1", "10.0.0.0/24"),
                                  row("A", "NET1", "10.0.1.0/24")),
                        "DUPLICATE_SCOPE_ID")

    def test_scope_id_can_repeat_across_tenants_only_when_network_disjoint(self):
        doc = inventory(row("A", "NET1", "10.0.0.0/24"),
                        row("B", "NET1", "10.0.1.0/24"))
        self.assertEqual(review_network_inventory(doc)["status"], "REVIEW_ONLY")

    def test_outside_rfc1918_ipv4_and_assigned_ula_hold(self):
        for bad in ("8.8.8.0/24", "1.1.1.1/32", "169.254.0.0/16",
                    "192.0.2.0/24", "198.18.0.0/15", "100.64.0.0/10",
                    "0.0.0.0/0", "224.0.0.0/4", "127.0.0.0/8",
                    "fc00::/8", "fe80::/10", "2001:db8::/32",
                    "::/0", "::ffff:10.0.0.1/128", "ff00::/8"):
            with self.subTest(bad=bad):
                self.assertHeld(inventory(row("A", "NET", bad)), "INVALID_NETWORK")

    def test_exact_host_prefix_ipv4_and_ipv6_accepted_as_shape(self):
        doc = inventory(row("A", "NET1", "192.168.2.8/32"),
                        row("B", "NET2", "fd02::1/128"))
        self.assertEqual(review_network_inventory(doc)["status"], "REVIEW_ONLY")

    def test_noncanonical_host_bit_cidrs_cannot_widen_scope(self):
        for bad in ("10.0.0.1/24", "172.16.1.1/16",
                    "192.168.0.1/16", "fd00::1/64"):
            self.assertHeld(inventory(row("A", "NET", bad)), "INVALID_NETWORK")

    def test_textual_aliases_are_rejected(self):
        for bad in ("010.0.0.0/8", "10.0.0.0/08", "192.168.0.0/024",
                    "FD00::/8", "fd00:0:0:0:0:0:0:0/8",
                    "10.0.0.0/255.0.0.0", "fd00::/008"):
            with self.subTest(value=bad):
                self.assertHeld(inventory(row("A", "NET", bad)), "INVALID_NETWORK")

    def test_url_port_zoneid_whitespace_and_nonliteral_rejected(self):
        for bad in ("https://10.1.2.3/32", "10.1.2.3:80",
                    "[fd00::1]/128", "fd00::%eth0/64", "10.0.0.0/8\n",
                    " 10.0.0.0/8", "localhost/32", "10.0.0.0",
                    "fd00::/8%wlan0", ""):
            self.assertHeld(inventory(row("A", "NET", bad)), "INVALID_NETWORK")

    def test_network_types_must_be_exact_strings(self):
        class StringSubclass(str):
            def strip(self):
                raise AssertionError("must never call subtype methods")
        for bad in (True, 1, 167772160, b"\x0a\x00\x00\x00",
                    None, [], {}, StringSubclass("10.0.0.0/8")):
            self.assertHeld(inventory(row("A", "NET", bad)), "INVALID_NETWORK")

    def test_record_shape_forbids_forged_authority(self):
        for extra in ("permit_issued", "owner_verified",
                      "authorization", "tenant_label", "approval_reference"):
            item = row("A", "NET", "10.0.0.0/8")
            item[extra] = True
            self.assertHeld(inventory(item), "INVALID_RECORD_SHAPE")

    def test_missing_field_and_nonobject_record_holds(self):
        for item in (None, True, 7, "x", {}, {"cidr": "10.0.0.0/8"}):
            self.assertHeld(inventory(item), "INVALID_RECORD_SHAPE")

    def test_tenant_and_scope_identity_exact_ascii_shape(self):
        for bad in ("", "a", "A" * 25, "A B", "A\x00", "A\n",
                    "a-b", "À", "A\u200b", 1, True, b"A", None):
            for field in ("tenant_id", "scope_id"):
                item = row("A", "NET", "10.0.0.0/8")
                item[field] = bad
                self.assertHeld(inventory(item), "INVALID_IDENTITY_SHAPE")

    def test_root_schema_is_exact_and_boolean_is_not_version(self):
        for value in (True, False, "1", 1.0, 0, None, 2):
            obj = inventory(row("A", "NET", "10.0.0.0/8"))
            obj["schema_version"] = value
            self.assertHeld(obj, "INVALID_DOCUMENT_SHAPE")
        for value in (None, True, [], {}, {"schema_version": 1}):
            self.assertHeld(value, "INVALID_DOCUMENT_SHAPE")

    def test_empty_and_oversized_record_collections_hold(self):
        for bad in ([], [row("A", f"NET{i}", "10.0.0.0/24")
                         for i in range(MAX_RECORDS + 1)],
                    None, 7, "records", {}, ()):
            doc = {"schema_version": 1, "networks": bad}
            self.assertHeld(doc, "INVALID_RECORD_COUNT")

    def test_json_duplicate_key_and_nonfinite_denied(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"networks":[{"tenant_id":"A","tenant_id":"B"}]}',
                    b'{"schema_version":NaN,"networks":[]}',
                    b'{"networks":Infinity}'):
            with self.assertRaises(ValueError):
                parse_json(raw)

    def test_json_invalid_ascii_and_size_limit_denied(self):
        for raw in (b"", b"\xff\xfe", b"x" * (MAX_BYTES + 1),
                    "{}", bytearray(b"{}"), None):
            with self.assertRaises(ValueError):
                parse_json(raw)

    def test_no_dns_or_sockets_for_any_decision(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                for doc in (inventory(row("A", "NET1", "10.0.0.0/8")),
                            inventory(row("A", "NET1", "8.8.8.0/24"))):
                    self.assertNoAuthority(review_network_inventory(doc))

    def test_review_does_not_mutate_caller_data(self):
        document = inventory(row("A", "NET1", "10.0.0.0/24"),
                             row("B", "NET2", "10.0.1.0/24"))
        original = copy.deepcopy(document)
        self.assertEqual(review_network_inventory(document),
                         review_network_inventory(document))
        self.assertEqual(document, original)

    def test_property_fuzz_nonoverlap_and_overlap(self):
        rng = random.Random(0xA13)
        for _ in range(100):
            a, b = rng.sample(range(0, 255), 2)
            network_a = f"10.42.{a}.0/24"
            network_b = f"10.42.{b}.0/24"
            disjoint = review_network_inventory(inventory(
                row("A", "ONE", network_a), row("B", "TWO", network_b)))
            self.assertEqual(disjoint["status"], "REVIEW_ONLY")
            nested = review_network_inventory(inventory(
                row("A", "ONE", f"10.42.{a}.0/24"),
                row("B", "TWO", f"10.42.{a}.128/25")))
            self.assertEqual(nested["status"], "HOLD")

    def _cli(self, data, *args):
        raw = data if type(data) is bytes else json.dumps(data).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=raw,
                              capture_output=True, check=False, timeout=6)

    def test_cli_review_only_is_nonzero_and_privacy_preserving(self):
        p = self._cli(inventory(row("TENANT", "NET", "10.0.0.0/8")))
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_hold_is_nonzero_without_tenant_leaks(self):
        marker = "SECRET_TENANT"
        p = self._cli(inventory(row(marker, "NET1", "8.8.8.0/24")))
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNotIn(marker.encode(), p.stdout + p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_rejects_extra_args_duplicate_key_and_large_input(self):
        for raw, args in ((b"{}", ("--approve",)),
                          (b'{"schema_version":1,"schema_version":1}', ()),
                          (b"x" * (MAX_BYTES + 1), ())):
            p = self._cli(raw, *args)
            self.assertEqual(p.returncode, 2, p.stderr)
            self.assertNoAuthority(json.loads(p.stdout))

    def test_shell_and_cannot_use_review_only_as_scan_permission(self):
        cmd = f"{sys.executable} {SCRIPT} && echo NOT_AUTHORIZED"
        p = subprocess.run(["sh", "-c", cmd],
                           input=json.dumps(inventory(row(
                               "A", "NET", "10.0.0.0/8"))).encode("ascii"),
                           capture_output=True, check=False, timeout=6)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"NOT_AUTHORIZED", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
