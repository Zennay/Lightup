"""Offline acceptance for non-authorizing lab inventory scope narrowing."""
from __future__ import annotations

import json
from pathlib import Path
import random
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_inventory_narrowing_offline import review_narrowing

SCRIPT = ROOT / "scripts" / "check_scope_lab_inventory_narrowing_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def transition(previous=None, proposed=None):
    return {
        "schema_version": 1,
        "previous_lab_literals": ["127.0.0.1", "10.1.2.3", "fd00::1"]
        if previous is None else previous,
        "proposed_lab_literals": ["10.1.2.3"]
        if proposed is None else proposed,
    }


class LabInventoryNarrowingTests(unittest.TestCase):
    def assertNoAuthority(self, receipt):
        self.assertEqual(set(receipt), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(receipt[k] is False for k in FLAGS))
        self.assertNotIn("10.1.2.3", json.dumps(receipt))

    def test_proper_subset_is_review_only_without_grant(self):
        result = review_narrowing(transition())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_same_set_in_any_order_is_review_only_without_grant(self):
        result = review_narrowing(transition(
            proposed=["fd00::1", "10.1.2.3", "127.0.0.1"],
        ))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_added_address_fails_whole_transition(self):
        result = review_narrowing(transition(
            proposed=["10.1.2.3", "10.1.2.4"],
        ))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SCOPE_WIDENING")
        self.assertNoAuthority(result)

    def test_added_address_after_removal_still_widens(self):
        result = review_narrowing(transition(
            previous=["10.1.2.3", "10.1.2.4"],
            proposed=["10.1.2.4", "192.168.1.1"],
        ))
        self.assertEqual(result["status"], "HOLD")
        self.assertNoAuthority(result)

    def test_duplicate_previous_or_proposed_literals_holds(self):
        for key in ("previous_lab_literals", "proposed_lab_literals"):
            doc = transition()
            doc[key] = ["10.1.2.3", "10.1.2.3"]
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_empty_old_and_new_never_make_positive_vacuous_subset(self):
        for key in ("previous_lab_literals", "proposed_lab_literals"):
            doc = transition()
            doc[key] = []
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_noncanonical_legacy_or_proposed_literal_holds(self):
        for value in ("FD00::1", "fd00:0:0:0:0:0:0:1", "127.000.0.1",
                      "127.0.0.1\t", "127.0.0.1:1234", "fd00::1%eth0",
                      "http://127.0.0.1", "127.0.0.1/32"):
            for key in ("previous_lab_literals", "proposed_lab_literals"):
                with self.subTest(value=value, key=key):
                    doc = transition()
                    doc[key] = [value]
                    self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_special_use_ips_not_members_even_when_old_and_new_agree(self):
        for value in ("169.254.1.2", "::ffff:10.1.2.3", "fe80::1",
                      "2001:db8::1", "8.8.8.8", "0.0.0.0", "fc00::1"):
            result = review_narrowing(transition([value], [value]))
            self.assertEqual(result["status"], "HOLD")
            self.assertNoAuthority(result)

    def test_schema_is_exact_and_rejects_fake_approvals(self):
        for added in ({"authorization_verified": True},
                      {"consent": "claimed"}, {"tenant": "claimed"},
                      {"proposed": ["10.1.2.3"]}):
            doc = transition()
            doc.update(added)
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_schema_version_requires_exact_integer_one(self):
        for value in (True, False, 1.0, "1", 0, None, 2):
            doc = transition()
            doc["schema_version"] = value
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_polymorphic_json_value_and_collection_shapes_denied(self):
        class StringSubclass(str):
            pass
        for bad in (StringSubclass("10.1.2.3"), 123, b"10.1.2.3", None,
                    True, 1.1):
            doc = transition()
            doc["proposed_lab_literals"] = [bad]
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")
        for bad in ({"literal": "10.1.2.3"}, "10.1.2.3", (),
                    ["10.1.2.3"] * 33, None):
            doc = transition()
            doc["proposed_lab_literals"] = bad
            self.assertEqual(review_narrowing(doc)["status"], "HOLD")

    def test_unknown_document_shapes_denied(self):
        for bad in (True, 123, None, [], {}, {"schema_version": 1}):
            self.assertEqual(review_narrowing(bad)["status"], "HOLD")

    def test_repeated_revisions_are_deterministic_and_no_state_is_cached(self):
        doc = transition()
        first = review_narrowing(doc)
        self.assertEqual(first, review_narrowing(doc))
        doc["proposed_lab_literals"] = ["10.1.2.4"]
        self.assertEqual(review_narrowing(doc)["status"], "HOLD")
        doc["proposed_lab_literals"] = ["10.1.2.3"]
        self.assertEqual(review_narrowing(doc), first)

    def test_deterministic_random_subsets_and_single_additions(self):
        rng = random.Random(1337)
        pool = [f"10.0.0.{i}" for i in range(1, 33)]
        for _ in range(120):
            previous = rng.sample(pool, rng.randrange(1, 33))
            proposed = rng.sample(previous, rng.randrange(1, len(previous) + 1))
            self.assertEqual(review_narrowing(transition(previous, proposed))["status"],
                             "REVIEW_ONLY")
            absent = next((value for value in pool if value not in previous), None)
            if absent is not None:
                proposed.append(absent)
                self.assertEqual(review_narrowing(transition(previous, proposed))["status"],
                                 "HOLD")

    def test_no_dns_or_socket_dependency(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNoAuthority(review_narrowing(transition()))
                self.assertNoAuthority(review_narrowing(transition(
                    proposed=["10.1.2.4"])))

    def _cli(self, document, *extra):
        data = document if type(document) is bytes else json.dumps(document).encode()
        return subprocess.run([sys.executable, str(SCRIPT), *extra],
                              input=data, capture_output=True, timeout=5, check=False)

    def test_cli_review_only_is_deliberately_nonzero(self):
        p = self._cli(transition())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_hold_is_nonzero_and_never_leaks_inputs(self):
        private = "PRIVATE-ASSET-MARKER"
        p = self._cli(transition(proposed=[private]))
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(private.encode(), p.stdout + p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_rejects_argument_and_oversized_json(self):
        p = self._cli(transition(), "--approve")
        self.assertEqual(p.returncode, 2)
        self.assertNoAuthority(json.loads(p.stdout))
        p = self._cli(b"x" * 8193)
        self.assertEqual(p.returncode, 2)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_shell_chain_cannot_infer_scan_authority(self):
        command = f"{sys.executable} {SCRIPT} && echo SHOULD_NOT_RUN"
        p = subprocess.run(["sh", "-c", command],
                           input=json.dumps(transition()).encode("ascii"),
                           capture_output=True, check=False, timeout=5)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"SHOULD_NOT_RUN", p.stdout + p.stderr)

    def test_input_dict_is_never_mutated(self):
        doc = transition()
        original = json.dumps(doc)
        result = review_narrowing(doc)
        self.assertNoAuthority(result)
        self.assertEqual(json.dumps(doc), original)


if __name__ == "__main__":
    unittest.main()
