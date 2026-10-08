"""Offline contract checks only; do not grant runtime audit-log access."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_audit_retention_boundary.json"


def reference_decision(request_tenant, event_tenant, role, action):
    """Intentionally isolated reference; never an authorization implementation."""
    if type(request_tenant) is not str or not request_tenant.strip():
        return "deny"
    if type(event_tenant) is not str or not event_tenant.strip():
        return "deny"
    if request_tenant != event_tenant:
        return "deny"
    if role not in ("client", "operator") or type(role) is not str:
        return "deny"
    if action == "read":
        return "allow"
    if action == "export" and role == "operator":
        return "allow"
    return "deny"


class AuditRetentionBoundaryContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_schema_and_unique_cases(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["contract"], "scope-authorization-audit-retention")
        ids = [row["id"] for row in self.data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 8)

    def test_each_case_has_exact_fields(self):
        required = {"id", "request_tenant", "event_tenant", "role", "action", "expected"}
        for case in self.data["cases"]:
            with self.subTest(case=case.get("id")):
                self.assertEqual(set(case), required)
                self.assertIn(case["expected"], ("allow", "deny"))

    def test_reference_case_matrix(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(reference_decision(case["request_tenant"], case["event_tenant"], case["role"], case["action"]), case["expected"])

    def test_type_confusion_denied(self):
        for value in (None, False, 1, [], {}, " "):
            with self.subTest(value=value):
                self.assertEqual(reference_decision(value, "tenant-a", "operator", "read"), "deny")
                self.assertEqual(reference_decision("tenant-a", value, "operator", "read"), "deny")

    def test_unknown_roles_and_actions_denied(self):
        for role in ("admin", "auditor", "", None, True):
            with self.subTest(role=role):
                self.assertEqual(reference_decision("tenant-a", "tenant-a", role, "export"), "deny")
        for action in ("delete", "purge", "download", "", None):
            with self.subTest(action=action):
                self.assertEqual(reference_decision("tenant-a", "tenant-a", "operator", action), "deny")


if __name__ == "__main__":
    unittest.main()
