"""Synthetic tests: time-window and network collisions, never scan authority."""
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
from scripts.check_scope_tenant_window_conflicts_offline import review_window_plan

SCRIPT = ROOT / "scripts" / "check_scope_tenant_window_conflicts_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def row(tenant="ALPHA", scope="NET1", cidr="10.1.2.0/24",
        start="2026-10-14T08:00:00Z", end="2026-10-14T09:00:00Z"):
    return {"tenant_id": tenant, "scope_id": scope, "cidr": cidr,
            "starts_at": start, "ends_at": end}


def plan(*rows):
    return {"schema_version": 1, "windows": list(rows)}


class TenantWindowConflictsTests(unittest.TestCase):
    def assertNoAuthority(self, r):
        self.assertEqual(set(r), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(r[k] is False for k in FLAGS))
        self.assertNotIn("ALPHA", json.dumps(r))

    def hold(self, p, reason=None):
        result = review_window_plan(p)
        self.assertEqual(result["status"], "HOLD", result)
        if reason:
            self.assertEqual(result["reason"], reason)
        self.assertNoAuthority(result)

    def test_single_canonical_utc_window_review_only(self):
        r = review_window_plan(plan(row()))
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_same_cidr_simultaneous_different_tenant_holds(self):
        self.hold(plan(row(), row("BETA", "NET2")),
                  "OVERLAPPING_NETWORK_WINDOW")

    def test_same_cidr_touching_half_open_windows_review_only(self):
        r = review_window_plan(plan(
            row(), row("BETA", "NET2", start="2026-10-14T09:00:00Z",
                       end="2026-10-14T10:00:00Z")))
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_one_second_overlap_holds(self):
        self.hold(plan(
            row(), row("BETA", "NET2", start="2026-10-14T08:59:59Z",
                       end="2026-10-14T09:59:59Z")),
            "OVERLAPPING_NETWORK_WINDOW")

    def test_same_time_disjoint_network_review_only(self):
        result = review_window_plan(plan(
            row(), row("BETA", "NET2", cidr="10.1.3.0/24")))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_parent_child_same_time_holds(self):
        self.hold(plan(row(cidr="10.1.0.0/16"),
                       row("BETA", "NET2", cidr="10.1.2.0/24")),
                  "OVERLAPPING_NETWORK_WINDOW")

    def test_nested_network_nonoverlapping_time_review_only(self):
        result = review_window_plan(plan(
            row(cidr="10.1.0.0/16"),
            row("BETA", "NET2", cidr="10.1.2.0/24",
                start="2026-10-14T10:00:00Z",
                end="2026-10-14T11:00:00Z")))
        self.assertEqual(result["status"], "REVIEW_ONLY")

    def test_ipv6_ula_nested_simultaneous_holds(self):
        self.hold(plan(row(cidr="fd00::/48"),
                       row("BETA", "NET2", cidr="fd00::/64")),
                  "OVERLAPPING_NETWORK_WINDOW")

    def test_ipv6_disjoint_subnets_same_time_review_only(self):
        result = review_window_plan(plan(
            row(cidr="fd00::/64"),
            row("BETA", "NET2", cidr="fd00:0:0:1::/64")))
        self.assertEqual(result["status"], "REVIEW_ONLY")

    def test_ipv4_ipv6_same_timestamp_cannot_overlap(self):
        result = review_window_plan(plan(
            row(cidr="10.1.0.0/16"), row("BETA", "NET2", cidr="fd00::/48")))
        self.assertEqual(result["status"], "REVIEW_ONLY")

    def test_same_tenant_overlapping_scopes_also_hold(self):
        self.hold(plan(row(), row("ALPHA", "NET2")),
                  "OVERLAPPING_NETWORK_WINDOW")

    def test_duplicate_tenant_scope_identity_denied_even_different_time(self):
        self.hold(plan(row(), row(start="2026-10-14T09:00:00Z",
                                  end="2026-10-14T10:00:00Z")),
                  "INVALID_WINDOW_PLAN")

    def test_zero_length_and_reversed_ranges_holds(self):
        for a,b in (("2026-10-14T09:00:00Z","2026-10-14T09:00:00Z"),
                    ("2026-10-14T10:00:00Z","2026-10-14T09:00:00Z")):
            self.hold(plan(row(start=a,end=b)), "INVALID_WINDOW_PLAN")

    def test_more_than_24_hours_holds_but_exactly_24_reviewable(self):
        self.hold(plan(row(end="2026-10-15T08:00:01Z")),
                  "INVALID_WINDOW_PLAN")
        result = review_window_plan(plan(row(end="2026-10-15T08:00:00Z")))
        self.assertEqual(result["status"], "REVIEW_ONLY")

    def test_midnight_crossing_utc_window_overlap(self):
        self.hold(plan(
            row(start="2026-10-14T23:00:00Z",
                end="2026-10-15T01:00:00Z"),
            row("BETA", "NET2", start="2026-10-15T00:30:00Z",
                end="2026-10-15T01:30:00Z")),
            "OVERLAPPING_NETWORK_WINDOW")

    def test_offsets_leapseconds_fractions_local_time_denied(self):
        for bad in ("2026-10-14T08:00:00+00:00",
                    "2026-10-14T08:00:00.000Z",
                    "2026-10-14T08:00:60Z",
                    "2026-10-14T08:00:00",
                    "2026-10-14t08:00:00z",
                    "2026-10-14T8:00:00Z",
                    "2026-13-14T08:00:00Z",
                    "2026-02-30T08:00:00Z",
                    "2026-10-14T08:00:00Z\n"):
            self.hold(plan(row(start=bad)), "INVALID_WINDOW_PLAN")

    def test_untrusted_public_special_use_or_hostbit_cidr_denied(self):
        for cidr in ("8.8.8.0/24", "169.254.0.0/16", "fe80::/10",
                     "10.1.2.1/24", "fd00::1/64", "::ffff:10.1.2.3/128"):
            self.hold(plan(row(cidr=cidr)), "INVALID_WINDOW_PLAN")

    def test_time_string_subclass_and_wrong_types_denied(self):
        class FakeTime(str):
            pass
        for value in (FakeTime("2026-10-14T08:00:00Z"), True, 1,
                      b"2026-10-14T08:00:00Z", None, {}):
            self.hold(plan(row(start=value)), "INVALID_WINDOW_PLAN")

    def test_invalid_identity_and_extra_approval_metadata_denied(self):
        bad = row()
        bad["permit_issued"] = True
        self.hold(plan(bad), "INVALID_WINDOW_PLAN")
        self.hold(plan(row(tenant="alice")), "INVALID_WINDOW_PLAN")
        self.hold(plan(row(scope="NET 1")), "INVALID_WINDOW_PLAN")

    def test_wrong_schema_types_invalid_root_and_empty_plan_denied(self):
        for value in (True, "1", 1.0, 2, None):
            d = plan(row())
            d["schema_version"] = value
            self.hold(d, "INVALID_WINDOW_PLAN")
        for value in (None, True, [], {}, {"schema_version": 1},
                      {"schema_version": 1, "windows": []}):
            self.hold(value, "INVALID_WINDOW_PLAN")

    def test_exact_32_windows_and_last_record_overlap(self):
        entries = [row(scope=f"NET{i}", cidr=f"10.2.{i}.0/24")
                   for i in range(32)]
        self.assertEqual(review_window_plan(plan(*entries))["status"], "REVIEW_ONLY")
        entries[-1]["cidr"] = "10.2.0.128/25"
        self.hold(plan(*entries), "OVERLAPPING_NETWORK_WINDOW")

    def test_thirty_third_record_denied(self):
        entries = [row(scope=f"NET{i}", cidr=f"10.2.{i}.0/24")
                   for i in range(33)]
        self.hold(plan(*entries), "INVALID_WINDOW_PLAN")

    def test_no_dns_socket_or_input_mutation(self):
        p = plan(row(), row("BETA","NET2",cidr="10.1.3.0/24"))
        original = copy.deepcopy(p)
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")):
                r = review_window_plan(p)
        self.assertNoAuthority(r)
        self.assertEqual(p, original)

    def _cli(self, value, *args):
        data = value if type(value) is bytes else json.dumps(value).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=data, capture_output=True, timeout=5, check=False)

    def test_cli_review_only_nonzero_shell_exit(self):
        p = self._cli(plan(row()))
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_holds_malformed_ambiguous_or_oversized_input(self):
        for value in (b'{"schema_version":1,"schema_version":1}',
                      b'{"windows":[{"tenant_id":"A","tenant_id":"B"}]}',
                      b"\xff", b"x"*32769):
            p = self._cli(value)
            self.assertEqual(p.returncode, 2)
            self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_does_not_echo_private_tenant_or_target(self):
        marker = "PRIVATE_CUSTOMER_ID"
        p = self._cli(plan(row(tenant=marker, cidr="8.8.8.0/24")))
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(marker.encode(), p.stdout+p.stderr)

    def test_cli_arguments_and_shell_chain_never_authorize(self):
        p = self._cli(plan(row()), "--grant")
        self.assertEqual(p.returncode, 2)
        shell = subprocess.run(["sh","-c", f"{sys.executable} {SCRIPT} && echo UNLOCKED"],
                               input=json.dumps(plan(row())).encode("ascii"),
                               capture_output=True, timeout=5, check=False)
        self.assertEqual(shell.returncode, 3)
        self.assertNotIn(b"UNLOCKED",shell.stdout+shell.stderr)


if __name__ == "__main__":
    unittest.main()
