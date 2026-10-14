"""Cross-tool synthetic invariants for six UNTRUSTED offline lab scope helpers.

A REVIEW_ONLY value is still never an authorization, permit, scan, grant,
trusted audit attestation, customer permission or release approval.
"""
from __future__ import annotations

import hashlib
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
from scripts.check_scope_lab_literal_offline import review_literal
from scripts.check_scope_lab_inventory_offline import review_inventory
from scripts.check_scope_lab_inventory_narrowing_offline import review_narrowing
from scripts.check_scope_lab_inventory_history_offline import review_history
from scripts.check_scope_lab_inventory_chain_offline import review_chain
from scripts.check_scope_lab_inventory_chain_extension_offline import review_extension

DOMAIN = b"LIGHTUP-OFFLINE-LAB-CHAIN-V1\x00"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def make_chain(versions):
    rows, parent = [], None
    for index, values in enumerate(versions, start=1):
        raw = json.dumps({"version": index, "lab_literals": sorted(values),
                          "previous_digest": parent},
                         sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("ascii")
        digest = hashlib.sha256(DOMAIN + raw).hexdigest()
        rows.append({"version": index, "lab_literals": list(values),
                     "previous_digest": parent, "digest": digest})
        parent = digest
    return {"schema_version": 1, "revisions": rows}


def surfaces(literal):
    base = ["10.1.2.3", "127.0.0.1"]
    history = [base, [literal]]
    return (
        review_literal(literal),
        review_inventory({
            "schema_version": 1, "declared_lab_literals": [literal],
            "proposed_literals": [literal],
        }),
        review_narrowing({
            "schema_version": 1, "previous_lab_literals": base,
            "proposed_lab_literals": [literal],
        }),
        review_history({
            "schema_version": 1, "lab_literal_versions": history,
        }),
        review_chain(make_chain(history)),
        review_extension({
            "schema_version": 1,
            "previous_chain": make_chain(history),
            "candidate_chain": make_chain(history + [[literal]]),
        }),
    )


class OfflineLabCompositionTests(unittest.TestCase):
    def assertNoAuthority(self, result):
        self.assertEqual(set(result), {"schema_version", "status", "reason", *FLAGS}
                         if "address_class" not in result
                         else {"schema_version", "status", "reason",
                               "address_class", *FLAGS})
        self.assertTrue(all(result[key] is False for key in FLAGS))

    def test_every_review_surface_keeps_five_authority_flags_false(self):
        for literal in ("10.1.2.3", "127.0.0.1", "fd00::1", "8.8.8.8"):
            for result in surfaces(literal):
                self.assertNoAuthority(result)

    def test_public_literal_is_held_by_all_six_surfaces(self):
        for result in surfaces("8.8.8.8"):
            self.assertEqual(result["status"], "HOLD")

    def test_link_local_never_promoted_in_any_surface(self):
        for literal in ("169.254.1.1", "fe80::1"):
            for result in surfaces(literal):
                self.assertEqual(result["status"], "HOLD")

    def test_mapped_ipv6_never_promoted_in_any_surface(self):
        for literal in ("::ffff:127.0.0.1", "::ffff:10.1.2.3"):
            for result in surfaces(literal):
                self.assertEqual(result["status"], "HOLD")

    def test_multicast_and_unspecified_never_promoted(self):
        for literal in ("0.0.0.0", "::", "224.0.0.1", "ff02::1"):
            for result in surfaces(literal):
                self.assertEqual(result["status"], "HOLD")

    def test_representational_aliases_are_not_universally_accepted(self):
        for literal in ("FD00::1", "fd00:0:0:0:0:0:0:1",
                        "127.000.0.1", "[::1]", "127.0.0.1/32"):
            results = surfaces(literal)
            self.assertEqual([result["status"] for result in results[1:]],
                             ["HOLD"] * 5)

    def test_cross_tool_positive_same_canonical_literal(self):
        base = ["10.1.2.3", "127.0.0.1"]
        chain = make_chain([base, ["10.1.2.3"]])
        extension = make_chain([base, ["10.1.2.3"], ["10.1.2.3"]])
        results = (
            review_literal("10.1.2.3"),
            review_inventory({"schema_version": 1,
                              "declared_lab_literals": base,
                              "proposed_literals": ["10.1.2.3"]}),
            review_narrowing({"schema_version": 1,
                              "previous_lab_literals": base,
                              "proposed_lab_literals": ["10.1.2.3"]}),
            review_history({"schema_version": 1,
                            "lab_literal_versions": [base, ["10.1.2.3"]]}),
            review_chain(chain),
            review_extension({"schema_version": 1,
                              "previous_chain": chain,
                              "candidate_chain": extension}),
        )
        for result in results:
            self.assertEqual(result["status"], "REVIEW_ONLY")
            self.assertNoAuthority(result)

    def test_history_widening_refused_by_history_and_hash_chain(self):
        versions = [["10.1.2.3"], ["10.1.2.3", "10.1.2.4"], ["10.1.2.3"]]
        self.assertEqual(review_history({"schema_version": 1,
                                         "lab_literal_versions": versions})["status"], "HOLD")
        self.assertEqual(review_chain(make_chain(versions))["status"], "HOLD")

    def test_mutating_earlier_chain_payload_never_fools_extension(self):
        baseline = make_chain([["127.0.0.1", "10.1.2.3"], ["10.1.2.3"]])
        candidate = make_chain([["10.1.2.3"], ["10.1.2.3"], ["10.1.2.3"]])
        result = review_extension({"schema_version": 1,
                                   "previous_chain": baseline,
                                   "candidate_chain": candidate})
        self.assertEqual(result["status"], "HOLD")
        self.assertNoAuthority(result)

    def test_random_public_ipv4_class_never_positive_across_tools(self):
        rng = random.Random(8137)
        literals = [str(ipaddress.IPv4Address(rng.getrandbits(32)))
                    for _ in range(100)]
        for literal in literals:
            if review_literal(literal)["status"] != "HOLD":
                continue
            results = surfaces(literal)
            self.assertEqual([r["status"] for r in results], ["HOLD"] * 6)

    def test_random_ipv6_nonlab_class_never_positive_across_tools(self):
        rng = random.Random(8140)
        for _ in range(100):
            literal = str(ipaddress.IPv6Address(rng.getrandbits(128)))
            if review_literal(literal)["status"] != "HOLD":
                continue
            self.assertEqual([r["status"] for r in surfaces(literal)], ["HOLD"] * 6)

    def test_no_dns_or_socket_in_any_of_six_surfaces(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                for literal in ("10.1.2.3", "8.8.8.8"):
                    for result in surfaces(literal):
                        self.assertNoAuthority(result)

    def test_invalid_input_never_echoed_to_aggregated_receipts(self):
        marker = "CUSTOMER-SECRET-MARKER.example.invalid"
        for result in surfaces(marker):
            self.assertNotIn(marker, json.dumps(result))
            self.assertNoAuthority(result)

    def test_repeated_calls_do_not_generate_positive_authority(self):
        for _ in range(10):
            for result in surfaces("10.1.2.3"):
                self.assertNoAuthority(result)
            for result in surfaces("8.8.8.8"):
                self.assertNoAuthority(result)


if __name__ == "__main__":
    unittest.main()
