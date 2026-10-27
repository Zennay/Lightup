"""Real offline synthetic cross-binding tests: never mint tenant authorization."""
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
from scripts.check_scope_tenant_inventory_schedule_binding_offline import (
    review_inventory_schedule_binding,
)

SCRIPT = ROOT / "scripts" / "check_scope_tenant_inventory_schedule_binding_offline.py"
FLAGS = ("authorization_verified", "permit_issued", "execution_enabled",
         "merge_approved", "release_approved")


def network(tenant, scope, cidr):
    return {"tenant_id": tenant, "scope_id": scope, "cidr": cidr}


def interval(tenant, scope, cidr,
             start="2026-10-14T08:00:00Z", end="2026-10-14T09:00:00Z"):
    return {**network(tenant, scope, cidr),
            "starts_at": start, "ends_at": end}


def package():
    return {
        "schema_version": 1,
        "inventory": {
            "schema_version": 1,
            "networks": [
                network("ALPHA", "NET1", "10.20.0.0/24"),
                network("BETA", "NET2", "fd00::/64"),
            ],
        },
        "schedule": {
            "schema_version": 1,
            "windows": [
                interval("ALPHA", "NET1", "10.20.0.0/24"),
                interval("BETA", "NET2", "fd00::/64"),
            ],
        },
    }


class TenantInventoryScheduleBindingTests(unittest.TestCase):
    def noAuthority(self, value):
        self.assertEqual(set(value), {"schema_version", "status", "reason", *FLAGS})
        self.assertTrue(all(value[f] is False for f in FLAGS))
        self.assertNotIn("ALPHA", json.dumps(value))

    def hold(self, value, reason=None):
        response = review_inventory_schedule_binding(value)
        self.assertEqual(response["status"], "HOLD", response)
        if reason:
            self.assertEqual(response["reason"], reason)
        self.noAuthority(response)

    def test_exact_two_scope_binding_is_only_review_only(self):
        r = review_inventory_schedule_binding(package())
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.noAuthority(r)

    def test_order_of_self_declared_records_does_not_matter(self):
        value = package()
        value["schedule"]["windows"].reverse()
        r = review_inventory_schedule_binding(value)
        self.assertEqual(r["status"], "REVIEW_ONLY")
        self.noAuthority(r)

    def test_changed_schedule_tenant_label_refused(self):
        value = package()
        value["schedule"]["windows"][0]["tenant_id"] = "GAMMA"
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_changed_schedule_scope_id_refused(self):
        value = package()
        value["schedule"]["windows"][0]["scope_id"] = "NET3"
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_changed_schedule_cidr_to_disjoint_ip_refused(self):
        value = package()
        value["schedule"]["windows"][0]["cidr"] = "10.21.0.0/24"
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_narrower_schedule_network_without_matching_inventory_refused(self):
        value = package()
        value["schedule"]["windows"][0]["cidr"] = "10.20.0.0/25"
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_one_unscheduled_inventory_scope_refused(self):
        value = package()
        value["schedule"]["windows"].pop()
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_extra_scheduled_scope_refused(self):
        value = package()
        value["schedule"]["windows"].append(
            interval("GAMMA", "NET3", "172.16.10.0/24"))
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_same_scope_id_but_swapped_tenants_refused(self):
        value = package()
        value["schedule"]["windows"][0]["tenant_id"] = "BETA"
        value["schedule"]["windows"][1]["tenant_id"] = "ALPHA"
        self.hold(value, "INVENTORY_SCHEDULE_MISMATCH")

    def test_invalid_reserved_network_in_inventory_blocks_binding(self):
        value = package()
        value["inventory"]["networks"][0]["cidr"] = "8.8.8.0/24"
        self.hold(value, "INVALID_INVENTORY")

    def test_nested_overlap_in_inventory_refused_first(self):
        value = package()
        value["inventory"]["networks"][1]["cidr"] = "10.20.0.128/25"
        self.hold(value, "INVALID_INVENTORY")

    def test_malformed_utc_offset_in_schedule_blocks_binding(self):
        value = package()
        value["schedule"]["windows"][0]["starts_at"] = "2026-10-14T08:00:00+00:00"
        self.hold(value, "INVALID_WINDOW_SCHEDULE")

    def test_end_before_start_in_schedule_blocks_binding(self):
        value = package()
        value["schedule"]["windows"][0]["ends_at"] = "2026-10-14T07:59:59Z"
        self.hold(value, "INVALID_WINDOW_SCHEDULE")

    def test_temporal_collision_in_schedule_even_with_canonical_ip_refused(self):
        value = package()
        # Reusing the exact same network for a second tenant should fail
        # both standalone inventories and whole-input cross-binding.
        value["schedule"]["windows"][1]["cidr"] = "10.20.0.0/24"
        self.hold(value, "INVALID_WINDOW_SCHEDULE")

    def test_schedule_duplicate_tenant_scope_refused(self):
        value = package()
        value["schedule"]["windows"][1]["tenant_id"] = "ALPHA"
        value["schedule"]["windows"][1]["scope_id"] = "NET1"
        self.hold(value, "INVALID_WINDOW_SCHEDULE")

    def test_inventory_duplicated_tenant_scope_refused(self):
        value = package()
        value["inventory"]["networks"][1]["tenant_id"] = "ALPHA"
        value["inventory"]["networks"][1]["scope_id"] = "NET1"
        self.hold(value, "INVALID_INVENTORY")

    def test_extra_authorizing_root_field_refused(self):
        for key in ("consent", "permit_issued", "authorization_verified"):
            value = package()
            value[key] = True
            self.hold(value, "INVALID_BINDING_SHAPE")

    def test_schema_type_and_invalid_root_refused(self):
        for schema in (True, "1", 1.0, 2, None):
            value = package()
            value["schema_version"] = schema
            self.hold(value, "INVALID_BINDING_SHAPE")
        for value in (None, True, {}, [], {"schema_version": 1}):
            self.hold(value, "INVALID_BINDING_SHAPE")

    def test_missing_inventory_or_window_plan_denied(self):
        for key in ("inventory", "schedule"):
            value = package()
            value.pop(key)
            self.hold(value, "INVALID_BINDING_SHAPE")

    def test_pure_repeatable_no_mutation_or_network(self):
        value = package()
        original = copy.deepcopy(value)
        with patch.object(socket, "socket", side_effect=AssertionError("socket")):
            with patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS")):
                first = review_inventory_schedule_binding(value)
                self.assertEqual(first, review_inventory_schedule_binding(value))
        self.assertEqual(value, original)
        self.noAuthority(first)

    def _cli(self, doc, *args):
        raw = doc if type(doc) is bytes else json.dumps(doc).encode("ascii")
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              input=raw, capture_output=True, timeout=5, check=False)

    def test_cli_review_only_never_returns_success_zero(self):
        r = self._cli(package())
        self.assertEqual(r.returncode, 3, r.stderr)
        self.noAuthority(json.loads(r.stdout))

    def test_cli_bad_json_duplicate_keys_invalid_utf8_oversize(self):
        for doc in (b'{"schema_version":1,"schema_version":1}',
                    b"\xff", b"x"*32769):
            r = self._cli(doc)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.noAuthority(json.loads(r.stdout))

    def test_cli_fake_approval_flag_and_secret_redacted(self):
        value = package()
        marker = "PRIVATE_TENANT_CANARY_123"
        value["schedule"]["windows"][0]["tenant_id"] = marker
        r = self._cli(value)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(marker.encode(), r.stdout + r.stderr)
        approved = self._cli(package(), "--authorize")
        self.assertEqual(approved.returncode, 2)

    def test_cli_shell_chain_cannot_produce_target_authority(self):
        cmd = f"{sys.executable} {SCRIPT} && echo MUST_NOT_RUN"
        p = subprocess.run(["sh", "-c", cmd],
                           input=json.dumps(package()).encode("ascii"),
                           capture_output=True, timeout=5, check=False)
        self.assertEqual(p.returncode, 3)
        self.assertNotIn(b"MUST_NOT_RUN", p.stdout+p.stderr)


if __name__ == "__main__":
    unittest.main()
