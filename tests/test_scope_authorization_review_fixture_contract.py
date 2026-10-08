"""Offline structural checks for synthetic scope-authorization reviewer fixtures.

This checks the *contract data*, not ExecutionPolicy behavior or release readiness.
No imports from target-capable modules and no network operations.
"""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "docs" / "fixtures" / "scope-authorization-review-denials.json"
EXPECTED_IDS = frozenset({
    "unknown_approver", "self_approval", "missing_intent", "excluded_asset",
    "risk_above_ceiling", "cross_tenant", "noncanonical_identity",
    "revoked_before_dispatch", "widened_live_scope", "widened_live_time",
    "invalid_clock", "missing_ledger", "activation_off",
})
DENY = {"decision": "DENY", "handler_calls": 0, "outbound_requests": 0}


def validate_fixture(data):
    """Raise ValueError on malformed or weakened synthetic deny contracts."""
    if type(data) is not dict or set(data) != {
        "schema_version", "kind", "purpose", "real_target_activation",
        "default_assertions", "cases",
    }:
        raise ValueError("invalid fixture envelope")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("unsupported schema")
    if data["kind"] != "scope_authorization_offline_review_cases":
        raise ValueError("unknown fixture kind")
    if type(data["purpose"]) is not str or not data["purpose"].strip():
        raise ValueError("missing fixture purpose")
    if data["real_target_activation"] is not False:
        raise ValueError("real-target activation must be false")
    if data["default_assertions"] != DENY or any(
        type(data["default_assertions"].get(k)) is not type(v)
        for k, v in DENY.items()
    ):
        raise ValueError("unsafe defaults")
    cases = data["cases"]
    if type(cases) is not list or len(cases) != len(EXPECTED_IDS):
        raise ValueError("missing or duplicate cases")
    seen = set()
    for case in cases:
        if type(case) is not dict or set(case) != {"id", "condition", "expected"}:
            raise ValueError("invalid case shape")
        identifier = case["id"]
        if type(identifier) is not str or identifier not in EXPECTED_IDS or identifier in seen:
            raise ValueError("unknown or repeated case identifier")
        seen.add(identifier)
        if type(case["condition"]) is not str or not case["condition"].strip():
            raise ValueError("missing case description")
        if case["expected"] != DENY or type(case["expected"]) is not dict or any(
            type(case["expected"].get(k)) is not type(v) for k, v in DENY.items()
        ):
            raise ValueError("unsafe case expectations")
    if seen != EXPECTED_IDS:
        raise ValueError("incomplete case coverage")


class ScopeAuthorizationReviewFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_contract(self):
        validate_fixture(self.data)

    def test_reject_missing_denial_case(self):
        data = json.loads(json.dumps(self.data))
        data["cases"].pop()
        with self.assertRaises(ValueError):
            validate_fixture(data)

    def test_reject_duplicate_case(self):
        data = json.loads(json.dumps(self.data))
        data["cases"][-1] = data["cases"][0].copy()
        with self.assertRaises(ValueError):
            validate_fixture(data)

    def test_reject_activated_target_mode(self):
        data = json.loads(json.dumps(self.data))
        data["real_target_activation"] = True
        with self.assertRaises(ValueError):
            validate_fixture(data)

    def test_reject_handler_or_network_permission(self):
        for key in ("handler_calls", "outbound_requests"):
            data = json.loads(json.dumps(self.data))
            data["cases"][0]["expected"][key] = 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_fixture(data)

    def test_reject_numeric_boolean_alias(self):
        data = json.loads(json.dumps(self.data))
        data["default_assertions"]["handler_calls"] = False
        with self.assertRaises(ValueError):
            validate_fixture(data)


if __name__ == "__main__":
    unittest.main()
