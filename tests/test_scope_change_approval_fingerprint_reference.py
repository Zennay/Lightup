"""Offline reference contract: a human approval is bound to one exact scope snapshot.

This is deliberately NOT a production authorization gate. It is a test-only
executable model for future integration and must never be used to grant access.
"""
import hashlib
import json
import unittest


def fingerprint(scope):
    """Compute an audit identifier only for strictly typed, canonical scope input."""
    if type(scope) is not dict or set(scope) != {"engagement_id", "targets", "capabilities", "risk_level"}:
        raise ValueError("invalid scope keys")
    if type(scope["engagement_id"]) is not str or not scope["engagement_id"].strip():
        raise ValueError("invalid engagement")
    if type(scope["risk_level"]) is not int or scope["risk_level"] not in range(0, 6):
        raise ValueError("invalid risk level")
    for key in ("targets", "capabilities"):
        values = scope[key]
        if type(values) is not list or not values:
            raise ValueError("invalid scope list")
        if any(type(v) is not str or not v or v.strip() != v for v in values):
            raise ValueError("invalid list member")
        if len(set(values)) != len(values):
            raise ValueError("duplicate list member")
    normalized = dict(scope)
    normalized["targets"] = sorted(scope["targets"])
    normalized["capabilities"] = sorted(scope["capabilities"])
    serialized = json.dumps(normalized, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def approval_applies(approved_fingerprint, current_scope):
    """Fail closed on malformed scope or approval evidence."""
    if type(approved_fingerprint) is not str or len(approved_fingerprint) != 64:
        return False
    if any(c not in "0123456789abcdef" for c in approved_fingerprint):
        return False
    try:
        return fingerprint(current_scope) == approved_fingerprint
    except (ValueError, TypeError):
        return False


class ScopeChangeRequiresFreshApproval(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "engagement_id": "eng-123",
            "targets": ["app.example.test"],
            "capabilities": ["http-headers"],
            "risk_level": 1,
        }
        self.approved = fingerprint(self.scope)

    def test_exact_snapshot_approved(self):
        self.assertTrue(approval_applies(self.approved, self.scope))

    def test_scope_order_does_not_change_fingerprint(self):
        expanded = dict(self.scope, targets=["api.example.test", "app.example.test"])
        reversed_order = dict(expanded, targets=list(reversed(expanded["targets"])))
        self.assertEqual(fingerprint(expanded), fingerprint(reversed_order))

    def test_added_target_needs_fresh_approval(self):
        self.assertFalse(approval_applies(self.approved, dict(self.scope, targets=["app.example.test", "other.example.test"])))

    def test_changed_capability_needs_fresh_approval(self):
        self.assertFalse(approval_applies(self.approved, dict(self.scope, capabilities=["tls-baseline"])))

    def test_changed_risk_needs_fresh_approval(self):
        self.assertFalse(approval_applies(self.approved, dict(self.scope, risk_level=2)))

    def test_changed_engagement_needs_fresh_approval(self):
        self.assertFalse(approval_applies(self.approved, dict(self.scope, engagement_id="eng-456")))

    def test_malformed_scope_fails_closed(self):
        for candidate in (
            dict(self.scope, risk_level=True),
            dict(self.scope, targets="app.example.test"),
            dict(self.scope, targets=["app.example.test", "app.example.test"]),
            dict(self.scope, capabilities=[]),
            dict(self.scope, targets=[" app.example.test"]),
            dict(self.scope, extra="ignored"),
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(approval_applies(self.approved, candidate))

    def test_invalid_approval_evidence_fails_closed(self):
        for token in (None, "", "A" * 64, "0" * 63, "z" * 64, True):
            with self.subTest(token=token):
                self.assertFalse(approval_applies(token, self.scope))

    def test_source_mutation_cannot_retroactively_modify_snapshot(self):
        original = fingerprint(self.scope)
        self.scope["targets"].append("second.example.test")
        self.assertEqual(original, self.approved)
        self.assertFalse(approval_applies(self.approved, self.scope))


if __name__ == "__main__":
    unittest.main()
