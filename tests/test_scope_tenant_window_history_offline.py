"""Synthetic denial tests for self-reported UTC lab-window revision histories."""
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
from scripts.check_scope_tenant_window_history_offline import review_window_history

SCRIPT = ROOT / "scripts" / "check_scope_tenant_window_history_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def row(tenant="ALPHA", scope="LAB", cidr="10.2.0.0/24",
        start="2026-10-14T08:00:00Z", end="2026-10-14T10:00:00Z"):
    return {"tenant_id":tenant,"scope_id":scope,"cidr":cidr,
            "starts_at":start,"ends_at":end}


def plan(*records):
    return {"schema_version":1,"windows":list(records)}


A = plan(row())
B = plan(row(cidr="10.2.0.0/25",start="2026-10-14T08:30:00Z",
             end="2026-10-14T09:30:00Z"))
C = plan(row(cidr="10.2.0.0/26",start="2026-10-14T08:45:00Z",
             end="2026-10-14T09:15:00Z"))


def history(*plans):
    return {"schema_version":1,"versions":copy.deepcopy(list(plans) or [A,B,C])}


class TenantWindowHistoryTests(unittest.TestCase):
    def no_authority(self, r):
        self.assertEqual(set(r),{"schema_version","status","reason",*FLAGS})
        self.assertTrue(all(r[k] is False for k in FLAGS))
        self.assertNotIn("ALPHA",json.dumps(r))

    def held(self, doc, reason=None):
        r = review_window_history(doc)
        self.assertEqual(r["status"],"HOLD",r)
        self.no_authority(r)
        if reason is not None:
            self.assertEqual(r["reason"],reason)

    def test_two_step_narrowing_is_review_only(self):
        r = review_window_history(history(A,B))
        self.assertEqual(r["status"],"REVIEW_ONLY")
        self.no_authority(r)

    def test_three_step_narrowing_is_review_only(self):
        r = review_window_history(history())
        self.assertEqual(r["status"],"REVIEW_ONLY")
        self.no_authority(r)

    def test_four_step_narrowing_is_review_only(self):
        r = review_window_history(history(A,B,C,C))
        self.assertEqual(r["status"],"REVIEW_ONLY")
        self.no_authority(r)

    def test_unchanged_history_review_only_not_authority(self):
        r = review_window_history(history(A,A))
        self.assertEqual(r["status"],"REVIEW_ONLY")
        self.no_authority(r)

    def test_time_expansion_between_narrow_and_revert_holds(self):
        self.held(history(A,B,A),"NONMONOTONIC_WINDOW_HISTORY")

    def test_temporary_one_second_earlier_start_caught(self):
        altered = plan(row(cidr="10.2.0.0/25",
                           start="2026-10-14T08:29:59Z",
                           end="2026-10-14T09:30:00Z"))
        self.held(history(A,B,altered,B),"NONMONOTONIC_WINDOW_HISTORY")

    def test_temporary_one_second_later_end_caught(self):
        altered = plan(row(cidr="10.2.0.0/25",
                           start="2026-10-14T08:30:00Z",
                           end="2026-10-14T09:30:01Z"))
        self.held(history(A,B,altered,B),"NONMONOTONIC_WINDOW_HISTORY")

    def test_network_widening_then_revert_holds(self):
        expanded = plan(row(cidr="10.2.0.0/24",
                            start="2026-10-14T08:30:00Z",
                            end="2026-10-14T09:30:00Z"))
        self.held(history(A,B,expanded,B),"NONMONOTONIC_WINDOW_HISTORY")

    def test_tenant_reassignment_then_revert_holds(self):
        reassigned = plan(row(tenant="BETA"))
        self.held(history(A,reassigned,A),"NONMONOTONIC_WINDOW_HISTORY")

    def test_scope_added_then_removed_holds(self):
        extra = plan(row(),row("BETA","NET2","10.3.0.0/24"))
        self.held(history(A,extra,A),"NONMONOTONIC_WINDOW_HISTORY")

    def test_scope_removed_then_reintroduced_holds(self):
        first = plan(row(),row("BETA","NET2","10.3.0.0/24"))
        self.held(history(first,A,first),"NONMONOTONIC_WINDOW_HISTORY")

    def test_intermediate_overlapping_network_and_time_holds(self):
        extra = plan(row(),row("BETA","NET2","10.2.0.128/25"))
        self.held(history(A,extra,A),"INVALID_HISTORY_WINDOW_PLAN")

    def test_intermediate_public_or_special_use_cidr_holds(self):
        for bad in ("8.8.8.0/24","169.254.0.0/16","fe80::/10"):
            with self.subTest(cidr=bad):
                self.held(history(A,plan(row(cidr=bad)),A),
                          "INVALID_HISTORY_WINDOW_PLAN")

    def test_malformed_timestamps_cannot_be_ignored_mid_history(self):
        for bad in ("2026-10-14T08:00:00+00:00",
                    "2026-10-14T08:00:00.000Z",
                    "2026-02-30T08:00:00Z"):
            with self.subTest(time=bad):
                self.held(history(A,plan(row(start=bad)),A),
                          "INVALID_HISTORY_WINDOW_PLAN")

    def test_extra_authority_fields_at_any_revision_denied(self):
        d = history()
        d["versions"][1]["windows"][0]["permit_issued"] = True
        self.held(d,"INVALID_HISTORY_WINDOW_PLAN")

    def test_more_than_four_or_fewer_than_two_versions_denied(self):
        for values in ([],[A],[A,B,C,C,C]):
            self.held({"schema_version":1,"versions":values},"INVALID_HISTORY_LENGTH")

    def test_collection_schema_type_and_root_values_denied(self):
        for value in (None,True,1,"text",{}):
            self.held({"schema_version":1,"versions":value},"INVALID_HISTORY_LENGTH")
        for value in (True,"1",1.0,0,None):
            d = history()
            d["schema_version"] = value
            self.held(d,"INVALID_HISTORY_SHAPE")

    def test_unknown_root_fields_invalid(self):
        d=history()
        d["authorized"]=True
        self.held(d,"INVALID_HISTORY_SHAPE")
        self.held({"schema_version":1},"INVALID_HISTORY_SHAPE")

    def test_review_is_pure_and_deterministic(self):
        d=history()
        old=copy.deepcopy(d)
        first=review_window_history(d)
        self.assertEqual(first,review_window_history(d))
        self.assertEqual(d,old)
        d["versions"][2]=copy.deepcopy(A)
        self.held(d)
        self.assertEqual(review_window_history(old),first)

    def test_no_socket_or_dns_even_for_invalid_history(self):
        with patch.object(socket,"socket",side_effect=AssertionError("socket")):
            with patch.object(socket,"getaddrinfo",side_effect=AssertionError("dns")):
                self.no_authority(review_window_history(history()))
                self.no_authority(review_window_history(history(A,B,A)))

    def _cli(self, data, *args):
        raw=data if type(data) is bytes else json.dumps(data).encode("ascii")
        return subprocess.run([sys.executable,str(SCRIPT),*args],
                              input=raw,capture_output=True,timeout=5,check=False)

    def test_cli_review_only_returns_nonzero_three(self):
        p=self._cli(history())
        self.assertEqual(p.returncode,3,p.stderr)
        self.no_authority(json.loads(p.stdout))

    def test_cli_denial_does_not_echo_customer_labels(self):
        marker="PRIVATE_CUSTOMER_NETWORK_NAME"
        d=history()
        d["versions"][1]["windows"][0]["tenant_id"]=marker
        p=self._cli(d)
        self.assertEqual(p.returncode,2,p.stderr)
        self.assertNotIn(marker.encode(),p.stdout+p.stderr)

    def test_cli_bad_json_oversize_and_args_hold(self):
        for raw,args in ((b'{"schema_version":1,"schema_version":1}',()),
                         (b"\xff",()),(b"x"*32769,()),
                         (json.dumps(history()).encode("ascii"),("--approve",))):
            p=self._cli(raw,*args)
            self.assertEqual(p.returncode,2,p.stderr)
            self.no_authority(json.loads(p.stdout))

    def test_shell_condition_never_runs_next_action(self):
        cmd=f"{sys.executable} {SCRIPT} && echo ACTIVATE"
        p=subprocess.run(["sh","-c",cmd],
                         input=json.dumps(history()).encode("ascii"),
                         capture_output=True,timeout=5,check=False)
        self.assertEqual(p.returncode,3)
        self.assertNotIn(b"ACTIVATE",p.stdout+p.stderr)


if __name__ == "__main__":
    unittest.main()
