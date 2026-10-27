"""Standalone synthetic tests of tenant-scoped CIDR narrowing (no grants)."""
from __future__ import annotations

import copy
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
from scripts.check_scope_tenant_cidr_narrowing_offline import review_tenant_narrowing

SCRIPT = ROOT / "scripts" / "check_scope_tenant_cidr_narrowing_offline.py"
_FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
          "merge_approved", "release_approved")


def row(t, s, cidr):
    return {"tenant_id": t, "scope_id": s, "cidr": cidr}


def snapshot(*records):
    return {"schema_version": 1, "networks": list(records)}


def revision(prior=None, proposed=None):
    return {
        "schema_version": 1,
        "previous": snapshot(row("ALPHA", "N1", "10.0.0.0/24"),
                             row("BETA", "N2", "fd00::/48"))
        if prior is None else prior,
        "proposed": snapshot(row("ALPHA", "N1", "10.0.0.0/25"),
                             row("BETA", "N2", "fd00::/64"))
        if proposed is None else proposed,
    }


class TenantNetworkNarrowingTests(unittest.TestCase):
    def assertNoAuthority(self, r):
        self.assertEqual(set(r), {"schema_version", "status", "reason", *_FLAGS})
        self.assertTrue(all(r[f] is False for f in _FLAGS))
        self.assertNotIn("ALPHA", json.dumps(r))
        self.assertNotIn("10.0.0.0", json.dumps(r))

    def assertHold(self, d, reason=None):
        result = review_tenant_narrowing(d)
        self.assertEqual(result["status"], "HOLD", result)
        self.assertNoAuthority(result)
        if reason is not None:
            self.assertEqual(result["reason"], reason)

    def test_two_tenants_can_narrow_both_ipv4_and_ipv6_only_review(self):
        r = review_tenant_narrowing(revision())
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_unchanged_self_declared_snapshot_is_only_review(self):
        prior = snapshot(row("ALPHA", "N1", "192.168.1.0/24"))
        result = review_tenant_narrowing(revision(prior, copy.deepcopy(prior)))
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertNoAuthority(result)

    def test_drop_one_scope_is_review_only_not_permission(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"),
                         row("BETA", "N2", "fd00::/48"))
        new = snapshot(row("BETA", "N2", "fd00::/48"))
        r = review_tenant_narrowing(revision(prior, new))
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.assertNoAuthority(r)

    def test_add_new_scope_even_with_disjoint_network_holds(self):
        new = revision()["proposed"]
        new["networks"].append(row("GAMMA", "N3", "192.168.3.0/24"))
        self.assertHold(revision(proposed=new), "NEW_OR_REASSIGNED_SCOPE")

    def test_same_scope_id_moved_to_another_tenant_holds(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"))
        new = snapshot(row("BETA", "N1", "10.0.0.0/25"))
        self.assertHold(revision(prior, new), "NEW_OR_REASSIGNED_SCOPE")

    def test_scope_id_reused_by_different_tenant_holds_if_new_key(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"),
                         row("BETA", "N2", "172.16.0.0/24"))
        new = snapshot(row("ALPHA", "N1", "10.0.0.0/24"),
                       row("BETA", "N1", "172.16.0.0/24"))
        self.assertHold(revision(prior, new), "NEW_OR_REASSIGNED_SCOPE")

    def test_ipv4_supernet_expansion_holds(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/25"))
        new = snapshot(row("ALPHA", "N1", "10.0.0.0/24"))
        self.assertHold(revision(prior, new), "WIDENED_OR_CHANGED_NETWORK")

    def test_ipv6_supernet_expansion_holds(self):
        prior = snapshot(row("ALPHA", "N1", "fd00::/64"))
        new = snapshot(row("ALPHA", "N1", "fd00::/48"))
        self.assertHold(revision(prior, new), "WIDENED_OR_CHANGED_NETWORK")

    def test_disjoint_moved_ipv4_subnet_not_narrowing(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"))
        new = snapshot(row("ALPHA", "N1", "10.0.1.0/24"))
        self.assertHold(revision(prior, new), "WIDENED_OR_CHANGED_NETWORK")

    def test_even_smaller_but_outside_previous_range_holds(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"))
        new = snapshot(row("ALPHA", "N1", "10.0.1.0/28"))
        self.assertHold(revision(prior, new), "WIDENED_OR_CHANGED_NETWORK")

    def test_ipv4_to_ipv6_substitution_holds(self):
        prior = snapshot(row("ALPHA", "N1", "10.0.0.0/24"))
        new = snapshot(row("ALPHA", "N1", "fd00::/64"))
        self.assertHold(revision(prior, new), "WIDENED_OR_CHANGED_NETWORK")

    def test_new_snapshot_overlap_cannot_be_accepted(self):
        new = snapshot(row("ALPHA", "N1", "10.0.0.0/25"),
                       row("BETA", "N2", "10.0.0.0/24"))
        self.assertHold(revision(proposed=new), "INVALID_PROPOSED_INVENTORY")

    def test_corrupt_previous_snapshot_fails_before_transition(self):
        prev = snapshot(row("ALPHA", "N1", "10.0.0.1/24"))
        self.assertHold(revision(prior=prev), "INVALID_PREVIOUS_INVENTORY")

    def test_corrupt_proposed_snapshot_fails_before_transition(self):
        new = snapshot(row("ALPHA", "N1", "8.8.8.0/24"))
        self.assertHold(revision(proposed=new), "INVALID_PROPOSED_INVENTORY")

    def test_prior_network_overlap_holds(self):
        prev = snapshot(row("ALPHA", "N1", "10.0.0.0/8"),
                        row("BETA", "N2", "10.0.0.0/24"))
        self.assertHold(revision(prior=prev), "INVALID_PREVIOUS_INVENTORY")

    def test_duplicate_and_empty_scope_in_proposed_holds(self):
        new = snapshot(row("ALPHA", "N1", "10.0.0.0/25"),
                       row("ALPHA", "N1", "10.0.1.0/25"))
        self.assertHold(revision(proposed=new), "INVALID_PROPOSED_INVENTORY")
        self.assertHold(revision(proposed=snapshot()),
                        "INVALID_PROPOSED_INVENTORY")

    def test_extra_fake_approval_metadata_in_root_denied(self):
        for name in ("permit_issued", "authorization", "consent",
                     "scan_enabled", "release_approved"):
            doc = revision()
            doc[name] = True
            self.assertHold(doc, "INVALID_TRANSITION_SHAPE")

    def test_exact_schema_type_required(self):
        for value in (True, False, 1.0, "1", None, 0, 2):
            doc = revision()
            doc["schema_version"] = value
            self.assertHold(doc, "INVALID_TRANSITION_SHAPE")

    def test_non_dict_documents_and_missing_fields_hold(self):
        for doc in (None, True, 1, "", [], {}, {"schema_version": 1}):
            self.assertHold(doc, "INVALID_TRANSITION_SHAPE")

    def test_repeated_review_is_pure_and_previous_untrusted(self):
        doc = revision()
        prior = copy.deepcopy(doc)
        good = review_tenant_narrowing(doc)
        self.assertEqual(good, review_tenant_narrowing(doc))
        self.assertEqual(doc, prior)
        doc["previous"]["networks"][0]["cidr"] = "10.0.0.0/26"
        self.assertHold(doc, "WIDENED_OR_CHANGED_NETWORK")
        self.assertEqual(review_tenant_narrowing(prior), good)

    def test_deterministic_100_ipv4_narrowing_and_widening_pairs(self):
        rng = random.Random(0x881)
        for _ in range(100):
            offset = rng.randrange(1, 255)
            old = snapshot(row("ALPHA", "N1", f"10.55.{offset}.0/24"))
            narrowed = snapshot(row("ALPHA", "N1", f"10.55.{offset}.0/25"))
            self.assertEqual(review_tenant_narrowing(revision(old, narrowed))["status"],
                             "REVIEW_ONLY")
            widened = snapshot(row("ALPHA", "N1", f"10.55.{offset}.0/23"))
            # Depending on offset host bits, noncanonical CIDR or widened range,
            # but never an acceptable narrowing.
            self.assertEqual(review_tenant_narrowing(revision(old, widened))["status"],
                             "HOLD")

    def test_no_network_or_dns_calls_during_validation(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")):
                self.assertNoAuthority(review_tenant_narrowing(revision()))
                self.assertNoAuthority(review_tenant_narrowing(revision(
                    proposed=snapshot(row("ALPHA", "N1", "8.8.8.0/24")))))

    def _cli(self, obj, *args):
        data = obj if type(obj) is bytes else json.dumps(obj).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=data, capture_output=True, check=False, timeout=5)

    def test_cli_positive_shape_exits_nonzero_three(self):
        process = self._cli(revision())
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))

    def test_cli_denials_never_echo_tenant_identity(self):
        marker = "SECRET_CUSTOMER"
        doc = revision()
        doc["proposed"]["networks"][0]["tenant_id"] = marker
        process = self._cli(doc)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn(marker.encode(), process.stdout + process.stderr)
        self.assertNoAuthority(json.loads(process.stdout))

    def test_cli_malformed_json_duplicate_key_and_arg_denied(self):
        for raw, args in ((b'{"schema_version":1,"schema_version":1}', ()),
                          (b"\xff", ()),
                          (json.dumps(revision()).encode("ascii"), ("--approve",))):
            process = self._cli(raw, *args)
            self.assertEqual(process.returncode, 2)
            self.assertNoAuthority(json.loads(process.stdout))

    def test_cli_shell_chain_stops_before_downstream_canary(self):
        command = f"{sys.executable} {SCRIPT} && echo FORBIDDEN_NEXT_STEP"
        process = subprocess.run(["sh", "-c", command],
                                 input=json.dumps(revision()).encode("ascii"),
                                 capture_output=True, check=False, timeout=5)
        self.assertEqual(process.returncode, 3)
        self.assertNotIn(b"FORBIDDEN_NEXT_STEP", process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
