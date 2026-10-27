"""Synthetic non-authorizing acceptance for successive tenant CIDR revisions."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_tenant_cidr_history_offline import review_tenant_network_history

SCRIPT = ROOT / "scripts" / "check_scope_tenant_cidr_history_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def item(tenant, scope, cidr):
    return {"tenant_id": tenant, "scope_id": scope, "cidr": cidr}


def snapshot(*entries):
    return {"schema_version": 1, "networks": list(entries)}


A = snapshot(item("ALPHA", "N1", "10.0.0.0/24"),
             item("BETA", "N2", "fd00::/48"))
B = snapshot(item("ALPHA", "N1", "10.0.0.0/25"),
             item("BETA", "N2", "fd00::/64"))
C = snapshot(item("ALPHA", "N1", "10.0.0.0/26"),
             item("BETA", "N2", "fd00::/80"))
D = snapshot(item("ALPHA", "N1", "10.0.0.0/32"),
             item("BETA", "N2", "fd00::1/128"))


def history(*versions):
    return {"schema_version": 1,
            "versions": copy.deepcopy(list(versions) if versions else [A, B, C])}


class TenantCidrHistoryTests(unittest.TestCase):
    def assertNoAuthority(self, receipt):
        self.assertEqual(set(receipt),
                         {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(receipt[f] is False for f in FLAGS))
        self.assertNotIn("ALPHA", json.dumps(receipt))
        self.assertNotIn("10.0.0.0", json.dumps(receipt))

    def assertHold(self, document, reason=None):
        value = review_tenant_network_history(document)
        self.assertEqual(value["status"], "HOLD", value)
        self.assertNoAuthority(value)
        if reason is not None:
            self.assertEqual(value["reason"], reason)

    def test_valid_three_version_narrowing_shape_only(self):
        result = review_tenant_network_history(history())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_valid_four_version_narrowing_shape_only(self):
        result = review_tenant_network_history(history(A, B, C, D))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_equal_adjacent_versions_are_not_authorization(self):
        result = review_tenant_network_history(history(A, A))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_last_step_widening_even_if_back_to_original_holds(self):
        self.assertHold(history(A, B, A), "NONMONOTONIC_TENANT_HISTORY")

    def test_first_step_widening_then_revert_holds(self):
        extended = snapshot(item("ALPHA", "N1", "10.0.0.0/23"),
                            item("BETA", "N2", "fd00::/48"))
        self.assertHold(history(A, extended, A), "NONMONOTONIC_TENANT_HISTORY")

    def test_intermediate_same_tenant_network_move_holds(self):
        different = snapshot(item("ALPHA", "N1", "10.0.1.0/24"),
                             item("BETA", "N2", "fd00::/48"))
        self.assertHold(history(A, different, A), "NONMONOTONIC_TENANT_HISTORY")

    def test_add_new_tenant_then_remove_is_still_hold(self):
        extra = copy.deepcopy(A)
        extra["networks"].append(item("GAMMA", "N3", "192.168.40.0/24"))
        self.assertHold(history(A, extra, A), "NONMONOTONIC_TENANT_HISTORY")

    def test_reassign_scope_id_between_tenants_holds(self):
        moved = snapshot(item("DELTA", "N1", "10.0.0.0/24"),
                         item("BETA", "N2", "fd00::/48"))
        self.assertHold(history(A, moved, moved), "NONMONOTONIC_TENANT_HISTORY")

    def test_removed_scope_cannot_be_reintroduced_later(self):
        reduced = snapshot(item("BETA", "N2", "fd00::/48"))
        self.assertHold(history(A, reduced, A), "NONMONOTONIC_TENANT_HISTORY")

    def test_no_loopback_ip_public_or_linklocal_in_any_revision(self):
        for bad in ("127.0.0.0/8", "8.8.8.0/24", "fe80::/10",
                    "::ffff:10.0.0.1/128", "0.0.0.0/0"):
            with self.subTest(bad=bad):
                intermediate = snapshot(item("ALPHA", "N1", bad))
                self.assertHold(history(A, intermediate, C),
                                "INVALID_HISTORY_INVENTORY")

    def test_overlapping_intermediate_snapshot_holds_atomically(self):
        overlap = snapshot(item("ALPHA", "N1", "10.0.0.0/8"),
                           item("BETA", "N2", "10.0.0.0/24"))
        self.assertHold(history(A, overlap, A), "INVALID_HISTORY_INVENTORY")

    def test_invalid_last_snapshot_not_ignored(self):
        broken = snapshot(item("ALPHA", "N1", "10.0.0.1/24"))
        self.assertHold(history(A, B, broken), "INVALID_HISTORY_INVENTORY")

    def test_duplicate_scope_middle_snapshot_denied(self):
        broken = snapshot(item("ALPHA", "N1", "10.0.0.0/24"),
                          item("ALPHA", "N1", "10.0.1.0/24"))
        self.assertHold(history(A, broken, A), "INVALID_HISTORY_INVENTORY")

    def test_one_or_five_versions_rejected(self):
        for values in ((A,), (A, A, A, A, A), ()):
            self.assertHold(history(*values) if values else
                            {"schema_version": 1, "versions": []},
                            "INVALID_HISTORY_LENGTH")

    def test_non_array_version_collection_denied(self):
        for values in (None, 1, True, {}, (), "not a version list"):
            self.assertHold({"schema_version": 1, "versions": values},
                            "INVALID_HISTORY_LENGTH")

    def test_schema_type_and_forged_approvals_denied(self):
        for value in (True, False, "1", 1.0, 0, None):
            doc = history(A, B)
            doc["schema_version"] = value
            self.assertHold(doc, "INVALID_HISTORY_SHAPE")
        for field in ("consent", "permit_issued", "approved_by"):
            doc = history(A, B)
            doc[field] = True
            self.assertHold(doc, "INVALID_HISTORY_SHAPE")

    def test_nonobject_root_and_missing_versions_denied(self):
        for value in (None, True, [], 1, {}, {"schema_version": 1}):
            self.assertHold(value, "INVALID_HISTORY_SHAPE")

    def test_no_network_dns_or_real_target_side_effect(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNoAuthority(review_tenant_network_history(history()))
                self.assertNoAuthority(review_tenant_network_history(history(A, B, A)))

    def test_repeated_same_input_deterministic_and_pure(self):
        document = history()
        original = copy.deepcopy(document)
        value = review_tenant_network_history(document)
        self.assertEqual(value, review_tenant_network_history(document))
        self.assertEqual(document, original)
        document["versions"][2] = copy.deepcopy(A)
        self.assertHold(document)
        self.assertEqual(review_tenant_network_history(original), value)

    def _cli(self, value, *args):
        data = value if type(value) is bytes else json.dumps(value).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=data,
                              capture_output=True, check=False, timeout=6)

    def test_cli_positive_returns_nonzero_and_no_authority(self):
        process = self._cli(history())
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))

    def test_cli_rejected_private_marker_not_echoed(self):
        marker = "SECRET_CUSTOMER_NETWORK_SCOPE"
        document = history()
        document["versions"][1]["networks"][0]["tenant_id"] = marker
        process = self._cli(document)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn(marker.encode(), process.stdout + process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))

    def test_cli_duplicate_key_nonascii_oversize_and_args_denied(self):
        for raw, args in ((b'{"schema_version":1,"schema_version":1}', ()),
                          (b"\xff", ()), (b"x" * 32769, ()),
                          (json.dumps(history()).encode("ascii"), ("--approve",))):
            process = self._cli(raw, *args)
            self.assertEqual(process.returncode, 2)
            self.assertNoAuthority(json.loads(process.stdout))

    def test_shell_chain_never_activates_when_review_only(self):
        command = f"{sys.executable} {SCRIPT} && echo AUTHORIZED"
        p = subprocess.run(["sh", "-c", command],
                           input=json.dumps(history()).encode("ascii"),
                           capture_output=True, check=False, timeout=6)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"AUTHORIZED", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
