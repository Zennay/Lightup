"""Offline acceptance fixture for minimal scope-authorization audit records.

This does not import or exercise production authorization. It checks only the
proposed serialization contract; runtime enforcement belongs to source owners.
"""
import json
import unittest
from datetime import datetime, timezone

_ALLOWED = frozenset({
    "schema_version", "event_kind", "decision", "reason_code",
    "interaction", "timestamp_utc", "correlation_id",
})
_DECISIONS = frozenset({"allow", "deny"})
_INTERACTIONS = frozenset({"analysis", "passive_public", "lab_active", "target_active"})
_REASONS = frozenset({
    "authorized", "analysis_only", "passive_only", "lab_only",
    "missing_grant", "grant_invalid", "engagement_closed",
    "scope_asset_denied", "scope_capability_denied", "risk_denied",
    "resolver_unavailable", "policy_denied",
})


def validate_example(record):
    if type(record) is not dict or frozenset(record) != _ALLOWED:
        return False
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        return False
    if record["event_kind"] != "scope_authorization_decision":
        return False
    for key, accepted in (("decision", _DECISIONS),
                          ("interaction", _INTERACTIONS),
                          ("reason_code", _REASONS)):
        if type(record[key]) is not str or record[key] not in accepted:
            return False
    if type(record["correlation_id"]) is not str:
        return False
    token = record["correlation_id"]
    if not (16 <= len(token) <= 64 and all(c in "0123456789abcdef" for c in token)):
        return False
    if type(record["timestamp_utc"]) is not str:
        return False
    try:
        parsed = datetime.fromisoformat(record["timestamp_utc"].replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0


class AuditSchemaFixtureTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(
            schema_version=1,
            event_kind="scope_authorization_decision",
            decision="deny",
            reason_code="missing_grant",
            interaction="target_active",
            timestamp_utc="2026-10-08T00:00:00Z",
            correlation_id="0123456789abcdef0123456789abcdef",
        )

    def test_valid_minimal_denial_serializes_without_sensitive_values(self):
        self.assertTrue(validate_example(self.record))
        encoded = json.dumps(self.record, sort_keys=True)
        for secret in ("https://target.example.test/path", "Bearer secret",
                       "password=secret", "Authorization:", "grant-private"):
            self.assertNotIn(secret, encoded)

    def test_no_extra_sensitive_or_free_text_fields(self):
        for key in ("asset", "url", "grant_id", "arguments", "exception", "raw_reason"):
            with self.subTest(key=key):
                self.assertFalse(validate_example({**self.record, key: "secret"}))

    def test_bounded_reason_and_exact_scalar_types(self):
        invalid = [
            {"reason_code": "denied: Bearer secret"},
            {"schema_version": True},
            {"decision": "ALLOW"},
            {"interaction": "target_active;run"},
            {"timestamp_utc": "2026-10-08T00:00:00"},
            {"correlation_id": "client-supplied free text"},
        ]
        for patch in invalid:
            with self.subTest(patch=patch):
                self.assertFalse(validate_example({**self.record, **patch}))

    def test_missing_fields_and_non_dict_denied(self):
        for key in _ALLOWED:
            with self.subTest(key=key):
                self.assertFalse(validate_example({k: v for k, v in self.record.items() if k != key}))
        self.assertFalse(validate_example([]))


if __name__ == "__main__":
    unittest.main()
