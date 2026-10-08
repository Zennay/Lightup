"""Offline tests for privacy-minimal authorization decision indexing."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scope_audit_minimal_projection import encode_scope_decision, project_scope_decision

GOOD = {"decision_id": "d-1", "tenant_id": "t-1", "run_id": "r-1",
        "grant_id": "g-1", "outcome": "deny", "reason_code": "grant_revoked"}


class MinimalScopeDecisionTests(unittest.TestCase):
    def test_canonical_projection_and_determinism(self):
        self.assertEqual(project_scope_decision(GOOD), GOOD)
        self.assertEqual(encode_scope_decision(GOOD), encode_scope_decision(dict(reversed(list(GOOD.items())))))

    def test_no_source_mutation(self):
        source = GOOD.copy()
        projected = project_scope_decision(source)
        projected["tenant_id"] = "modified"
        self.assertEqual(source, GOOD)

    def test_unknown_sensitive_fields_rejected(self):
        for key in ("target_url", "authorization_token", "raw_evidence", "operator_email"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                project_scope_decision({**GOOD, key: "sensitive"})

    def test_missing_fields_rejected(self):
        for key in GOOD:
            with self.subTest(key=key), self.assertRaises(ValueError):
                project_scope_decision({k: v for k, v in GOOD.items() if k != key})

    def test_noncanonical_types_rejected(self):
        for value in (None, [], True, 1, dict(GOOD, tenant_id=1), dict(GOOD, outcome=True)):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                project_scope_decision(value)

    def test_invalid_outcomes_and_reason_rejected(self):
        for value in ("approved", "ALLOW", "", " allow"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                project_scope_decision({**GOOD, "outcome": value})
        for value in ("foo/bar", "foo.bar", "foo bar", "-"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                project_scope_decision({**GOOD, "reason_code": value})

    def test_control_characters_and_overlength_rejected(self):
        for value in ("line\nbreak", "leading space", "é", "x" * 129):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                project_scope_decision({**GOOD, "run_id": value})


if __name__ == "__main__":
    unittest.main()
