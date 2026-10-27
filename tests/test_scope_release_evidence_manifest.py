"""Offline consistency tests for the non-executable scope release evidence manifest.

The catalog is descriptive: passing these checks NEVER authorizes a release.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest


CATALOG = Path(__file__).resolve().parents[1] / "docs/security/scope-authorization-release-gates.json"
REQUIRED_GATES = {
    "tenant_lineage",
    "elevated_issuance",
    "activation_current_grant",
    "durable_read_integrity",
    "executor_canonical_objects",
    "live_authority_monotonic",
    "time_argument_exactness",
    "scope_membership_precedes_authorization",
}
BAD_CONCLUSIONS = {"queued", "cancelled", "skipped", "failure", "timed_out", "stale_head"}


class ScopeReleaseManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(CATALOG.read_text(encoding="utf-8"))

    def test_never_confers_production_authority(self):
        m = self.manifest
        self.assertEqual(m["schema_version"], 1)
        self.assertEqual(m["stage"], "ST5_PLAN_LAB_ONLY")
        self.assertIs(m["production_authority"], False)
        self.assertEqual(m["default_decision"], "DENY")

    def test_exact_head_canonical_proof_is_mandatory(self):
        ci = self.manifest["ci"]
        for field in (
            "requires_exact_source_sha",
            "requires_exact_test_sha",
            "requires_canonical_self_hosted_success",
        ):
            with self.subTest(field=field):
                self.assertIs(ci[field], True)
        self.assertTrue(BAD_CONCLUSIONS.issubset(ci["reject_conclusions"]))

    def test_required_gates_have_unique_identifiers_and_dual_controls(self):
        gates = self.manifest["gates"]
        self.assertIs(type(gates), list)
        ids = [g["id"] for g in gates]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), REQUIRED_GATES)
        for gate in gates:
            with self.subTest(gate=gate["id"]):
                self.assertIs(type(gate["id"]), str)
                self.assertTrue(gate["negative"].strip())
                self.assertTrue(gate["positive"].strip())
                deps = gate["dependencies"]
                self.assertIs(type(deps), list)
                self.assertTrue(deps)
                self.assertEqual(len(deps), len(set(deps)))
                self.assertTrue(all(type(n) is int and n > 0 for n in deps))

    def test_denial_has_zero_side_effect_budget(self):
        self.assertEqual(
            self.manifest["on_denial"],
            {
                "target_handler_calls": 0,
                "network_calls": 0,
                "unauthorized_state_mutations": 0,
            },
        )


if __name__ == "__main__":
    unittest.main()
