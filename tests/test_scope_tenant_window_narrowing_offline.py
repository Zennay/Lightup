"""Synthetic zero-authority controls for tenant UTC test-window plan narrowing."""
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
from scripts.check_scope_tenant_window_narrowing_offline import review_window_narrowing

SCRIPT = ROOT / "scripts" / "check_scope_tenant_window_narrowing_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def row(tenant="ALPHA", scope="NET1", cidr="10.20.0.0/24",
        start="2026-10-14T08:00:00Z", end="2026-10-14T10:00:00Z"):
    return {"tenant_id": tenant, "scope_id": scope, "cidr": cidr,
            "starts_at": start, "ends_at": end}


def plan(*records):
    return {"schema_version": 1, "windows": list(records)}


def transition(previous=None, proposed=None):
    if previous is None:
        previous = plan(row(), row("BETA","NET2","fd00::/48"))
    if proposed is None:
        proposed = plan(
            row(cidr="10.20.0.0/25", start="2026-10-14T08:30:00Z",
                end="2026-10-14T09:30:00Z"),
            row("BETA", "NET2", "fd00::/64", start="2026-10-14T09:00:00Z",
                end="2026-10-14T10:00:00Z"),
        )
    return {"schema_version": 1, "previous": previous, "proposed": proposed}


class TenantWindowNarrowingTests(unittest.TestCase):
    def assertNoAuthority(self, r):
        self.assertEqual(set(r), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(r[k] is False for k in FLAGS))
        self.assertNotIn("ALPHA", json.dumps(r))

    def hold(self, d, reason=None):
        r = review_window_narrowing(d)
        self.assertEqual(r["status"], "HOLD", r)
        if reason:
            self.assertEqual(r["reason"], reason)
        self.assertNoAuthority(r)

    def test_positive_ipv4_and_ipv6_time_and_cidr_narrowing(self):
        r = review_window_narrowing(transition())
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_exact_unchanged_snapshot_reviewable_only(self):
        old = plan(row())
        r = review_window_narrowing(transition(old, copy.deepcopy(old)))
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_removing_one_scope_is_narrowing(self):
        old = plan(row(), row("BETA","NET2","fd00::/48"))
        new = plan(row())
        r = review_window_narrowing(transition(old,new))
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_start_moved_earlier_is_hold(self):
        new = plan(row(start="2026-10-14T07:59:59Z"))
        self.hold(transition(plan(row()),new),"EXPANDED_OR_MOVED_WINDOW")

    def test_end_moved_later_is_hold(self):
        new = plan(row(end="2026-10-14T10:00:01Z"))
        self.hold(transition(plan(row()),new),"EXPANDED_OR_MOVED_WINDOW")

    def test_shifted_same_length_later_is_not_narrowing(self):
        new = plan(row(start="2026-10-14T09:00:00Z",
                       end="2026-10-14T11:00:00Z"))
        self.hold(transition(plan(row()),new),"EXPANDED_OR_MOVED_WINDOW")

    def test_shifted_same_length_earlier_is_not_narrowing(self):
        new = plan(row(start="2026-10-14T07:00:00Z",
                       end="2026-10-14T09:00:00Z"))
        self.hold(transition(plan(row()),new),"EXPANDED_OR_MOVED_WINDOW")

    def test_network_widening_even_with_narrower_time_holds(self):
        old = plan(row(cidr="10.20.0.0/25"))
        new = plan(row(cidr="10.20.0.0/24",
                       start="2026-10-14T09:00:00Z",
                       end="2026-10-14T09:30:00Z"))
        self.hold(transition(old,new),"EXPANDED_OR_MOVED_WINDOW")

    def test_disjoint_network_move_even_with_shorter_time_holds(self):
        old = plan(row())
        new = plan(row(cidr="10.20.1.0/25",
                       start="2026-10-14T09:00:00Z",
                       end="2026-10-14T09:30:00Z"))
        self.hold(transition(old,new),"EXPANDED_OR_MOVED_WINDOW")

    def test_ip_family_swap_denied(self):
        new = plan(row(cidr="fd00::/64"))
        self.hold(transition(plan(row()),new),"EXPANDED_OR_MOVED_WINDOW")

    def test_tenant_swap_denied_even_if_all_else_same(self):
        old = plan(row())
        new = plan(row(tenant="BETA"))
        self.hold(transition(old,new),"NEW_OR_REASSIGNED_WINDOW_SCOPE")

    def test_new_scope_added_even_disjoint_time_network_holds(self):
        old = plan(row())
        new = plan(row(), row("BETA","NET2","10.21.0.0/24"))
        self.hold(transition(old,new),"NEW_OR_REASSIGNED_WINDOW_SCOPE")

    def test_same_tenant_new_scope_is_held(self):
        old = plan(row())
        new = plan(row(), row("ALPHA","NET2","10.21.0.0/24"))
        self.hold(transition(old,new),"NEW_OR_REASSIGNED_WINDOW_SCOPE")

    def test_previous_invalid_overlap_holds_first(self):
        old = plan(row(), row("BETA","NET2","10.20.0.128/25"))
        self.hold(transition(old,plan(row())),"INVALID_PREVIOUS_WINDOW_PLAN")

    def test_proposed_invalid_overlap_holds_before_transition(self):
        new = plan(row(), row("BETA","NET2","10.20.0.128/25"))
        self.hold(transition(plan(row()),new),"INVALID_PROPOSED_WINDOW_PLAN")

    def test_previous_malformed_date_holds(self):
        old = plan(row(start="2026-10-14T08:00:00+00:00"))
        self.hold(transition(old,plan(row())),"INVALID_PREVIOUS_WINDOW_PLAN")

    def test_proposed_malformed_date_holds(self):
        new = plan(row(end="2026-10-14T08:00:60Z"))
        self.hold(transition(plan(row()),new),"INVALID_PROPOSED_WINDOW_PLAN")

    def test_reassignment_hidden_as_scope_case_not_accepted(self):
        old = plan(row(scope="NET1"))
        new = plan(row(scope="net1"))
        self.hold(transition(old,new),"INVALID_PROPOSED_WINDOW_PLAN")

    def test_extra_root_approval_and_invalid_schema_denied(self):
        for key in ("authorization_verified", "permit_issued", "consent"):
            doc = transition()
            doc[key] = True
            self.hold(doc,"INVALID_TRANSITION_SHAPE")
        for value in (True, "1", 1.0, 0, None):
            doc = transition()
            doc["schema_version"] = value
            self.hold(doc,"INVALID_TRANSITION_SHAPE")

    def test_nondict_root_missing_fields_and_nonobject_snapshots(self):
        for value in (None, True, [], {}, {"schema_version": 1}):
            self.hold(value,"INVALID_TRANSITION_SHAPE")
        doc = transition()
        doc["previous"] = "not-a-plan"
        self.hold(doc,"INVALID_PREVIOUS_WINDOW_PLAN")

    def test_review_deterministic_pure_no_network_dns(self):
        doc = transition()
        saved = copy.deepcopy(doc)
        with patch.object(socket, "socket", side_effect=AssertionError("network")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")):
                result = review_window_narrowing(doc)
                self.assertEqual(review_window_narrowing(doc),result)
        self.assertEqual(saved,doc)
        self.assertNoAuthority(result)

    def _cli(self, obj, *args):
        raw = obj if type(obj) is bytes else json.dumps(obj).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=raw,capture_output=True,timeout=5,check=False)

    def test_cli_positive_is_nonzero_never_authorizing(self):
        p = self._cli(transition())
        self.assertEqual(p.returncode,3,p.stderr)
        self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_bad_arg_oversize_duplicate_key_utf8_hold(self):
        for raw,args in ((b'{"schema_version":1,"schema_version":1}',()),
                         (b"\xff",()),
                         (b"x"*32769,()),
                         (json.dumps(transition()).encode("ascii"),("--permit",))):
            p = self._cli(raw,*args)
            self.assertEqual(p.returncode,2,p.stderr)
            self.assertNoAuthority(json.loads(p.stdout))

    def test_cli_no_private_labels_echoed(self):
        marker = "PRIVATE_CUSTOMER_IDENTIFIER"
        p = self._cli(transition(proposed=plan(row(tenant=marker))))
        self.assertEqual(p.returncode,2,p.stderr)
        self.assertNotIn(marker.encode(),p.stdout+p.stderr)

    def test_cli_shell_and_never_runs_next_command(self):
        cmd = f"{sys.executable} {SCRIPT} && echo MUST_NOT_RUN"
        p = subprocess.run(["sh","-c",cmd],
                           input=json.dumps(transition()).encode("ascii"),
                           capture_output=True,timeout=5,check=False)
        self.assertEqual(p.returncode,3)
        self.assertNotIn(b"MUST_NOT_RUN",p.stdout+p.stderr)


if __name__ == "__main__":
    unittest.main()
