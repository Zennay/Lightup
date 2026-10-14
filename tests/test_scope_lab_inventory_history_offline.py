"""Offline 2–4-version scope-narrowing history acceptance, all non-authorizing."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.check_scope_lab_inventory_history_offline import review_history

SCRIPT = ROOT / "scripts" / "check_scope_lab_inventory_history_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def packet(versions=None):
    return {
        "schema_version": 1,
        "lab_literal_versions": versions if versions is not None else [
            ["127.0.0.1", "10.1.2.3", "fd00::1"],
            ["127.0.0.1", "10.1.2.3"],
            ["10.1.2.3"],
        ],
    }


class LabInventoryHistoryTests(unittest.TestCase):
    def assertNeverAuthorized(self, result):
        self.assertEqual(set(result), {"schema_version", "status", "reason", *FLAGS})
        self.assertEqual(result["schema_version"], 1)
        self.assertTrue(all(result[key] is False for key in FLAGS))
        self.assertNotIn("10.1.2.3", json.dumps(result))

    def test_two_step_valid_narrowing_is_only_review_only(self):
        result = review_history(packet([["10.1.2.3", "10.1.2.4"], ["10.1.2.3"]]))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNeverAuthorized(result)

    def test_three_step_valid_narrowing_is_review_only(self):
        result = review_history(packet())
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNeverAuthorized(result)

    def test_four_step_equal_then_narrow_is_review_only(self):
        versions = [
            ["127.0.0.1", "10.1.2.3", "fd00::1"],
            ["fd00::1", "127.0.0.1", "10.1.2.3"],
            ["127.0.0.1", "10.1.2.3"],
            ["10.1.2.3"],
        ]
        self.assertEqual(review_history(packet(versions))["status"], "REVIEW_ONLY")

    def test_transient_expansion_even_when_reverted_is_hold(self):
        versions = [
            ["10.1.2.3"],
            ["10.1.2.3", "10.1.2.4"],
            ["10.1.2.3"],
        ]
        result = review_history(packet(versions))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "TRANSIENT_SCOPE_WIDENING")
        self.assertNeverAuthorized(result)

    def test_third_version_expansion_even_if_final_is_subset_is_hold(self):
        versions = [
            ["10.1.2.3", "10.1.2.4"],
            ["10.1.2.3"],
            ["10.1.2.3", "10.1.2.4"],
            ["10.1.2.3"],
        ]
        self.assertEqual(review_history(packet(versions))["status"], "HOLD")

    def test_replacement_is_not_equivalent_to_narrowing(self):
        versions = [["10.1.2.3", "10.1.2.4"], ["10.1.2.4", "192.168.1.1"]]
        self.assertEqual(review_history(packet(versions))["status"], "HOLD")

    def test_corrupt_intermediate_snapshot_cannot_be_ignored(self):
        for bad in (["8.8.8.8"], ["169.254.1.1"], ["::ffff:10.1.2.3"],
                    ["fd00:0:0:0:0:0:0:1"], ["10.1.2.3", "10.1.2.3"],
                    [], [None], ["10.1.2.3"] * 33):
            with self.subTest(bad=bad):
                result = review_history(packet([["10.1.2.3"], bad, ["10.1.2.3"]]))
                self.assertEqual(result["status"], "HOLD")
                self.assertNeverAuthorized(result)

    def test_more_than_four_or_fewer_than_two_versions_holds(self):
        for bad in ([], [["10.1.2.3"]], [["10.1.2.3"]] * 5, "10.1.2.3",
                    None, {}, (), 123, True):
            obj = packet()
            obj["lab_literal_versions"] = bad
            self.assertEqual(review_history(obj)["status"], "HOLD")

    def test_missing_and_forged_permission_fields_fail_closed(self):
        for mutation in (
            lambda p: p.pop("lab_literal_versions"),
            lambda p: p.update(permit_issued=True),
            lambda p: p.update(authorization_verified=True),
            lambda p: p.update(owner="claimed"),
        ):
            doc = packet()
            mutation(doc)
            self.assertEqual(review_history(doc)["status"], "HOLD")

    def test_schema_version_never_coerces_bool_float_or_text(self):
        for value in (True, False, 1.0, "1", None, 0, 2):
            doc = packet()
            doc["schema_version"] = value
            self.assertEqual(review_history(doc)["status"], "HOLD")

    def test_noncanonical_ipv6_reserved_and_url_each_hold(self):
        for value in ("FD00::1", "fe80::1", "2001:db8::1",
                      "10.1.2.3:443", "http://10.1.2.3",
                      "10.1.2.3/32", "fd00::1%eth0"):
            self.assertEqual(
                review_history(packet([["10.1.2.3"], [value]]))["status"], "HOLD"
            )

    def test_non_object_input_fail_closed(self):
        for value in (None, [], True, 123, "{}", {}, {"schema_version": 1}):
            self.assertEqual(review_history(value)["status"], "HOLD")

    def test_no_dns_socket_dependencies_even_for_widened_series(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNeverAuthorized(review_history(packet()))
                self.assertNeverAuthorized(review_history(packet(
                    [["10.1.2.3"], ["10.1.2.3", "10.1.2.4"]]
                )))

    def test_input_is_not_mutated_or_snapshot_cached(self):
        doc = packet()
        original = json.dumps(doc)
        positive = review_history(doc)
        self.assertEqual(json.dumps(doc), original)
        doc["lab_literal_versions"][1].append("10.1.2.4")
        self.assertEqual(review_history(doc)["status"], "HOLD")
        doc = json.loads(original)
        self.assertEqual(review_history(doc), positive)

    def _cli(self, raw, *args):
        data = raw if type(raw) is bytes else json.dumps(raw).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=data, capture_output=True, timeout=5, check=False)

    def test_cli_review_only_exits_nonzero_three(self):
        proc = self._cli(packet())
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "REVIEW_ONLY")
        self.assertNeverAuthorized(json.loads(proc.stdout))

    def test_cli_hold_never_echoes_sensitive_asset_text(self):
        marker = "private-target-canary.example.invalid"
        proc = self._cli(packet([["10.1.2.3"], [marker]]))
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(marker.encode(), proc.stdout + proc.stderr)
        self.assertNeverAuthorized(json.loads(proc.stdout))

    def test_cli_invalid_duplicate_keys_and_oversize_hold(self):
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b"\xff\xfe", b"X" * 8193):
            proc = self._cli(raw)
            self.assertEqual(proc.returncode, 2)
            self.assertNeverAuthorized(json.loads(proc.stdout))

    def test_cli_argv_does_not_enable_authority(self):
        proc = self._cli(packet(), "--permit")
        self.assertEqual(proc.returncode, 2)
        self.assertNeverAuthorized(json.loads(proc.stdout))

    def test_shell_chain_does_not_turn_review_only_into_permission(self):
        cmd = f"{sys.executable} {SCRIPT} && echo MUST_NOT_RUN"
        proc = subprocess.run(["sh", "-c", cmd],
                              input=json.dumps(packet()).encode("ascii"),
                              capture_output=True, check=False, timeout=5)
        self.assertEqual(proc.returncode, 3)
        self.assertNotIn(b"MUST_NOT_RUN", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
