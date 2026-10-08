"""Strict offline fixture-shape gate; NEVER a runtime authorization or release gate."""
import json
from pathlib import Path
import sys

EXPECTED = {
    "AUD-01": "wrong_tenant",
    "AUD-02": "revoked_grant",
    "AUD-03": "token_bearing_url",
    "AUD-04": "secret_in_exception",
    "AUD-05": "audit_sink_unavailable",
    "AUD-06": "cross_tenant_read",
    "AUD-07": "unknown_event_field",
    "AUD-08": "malformed_target",
}
REQUIRED = {"event_id", "timestamp", "tenant_correlation_id", "reason_code", "policy_version"}
FORBIDDEN = {"url", "target", "headers", "body", "password", "secret", "cookie", "authorization", "access_token", "exception", "stack_trace"}


def no_duplicate_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def validate(text):
    obj = json.loads(text, object_pairs_hook=no_duplicate_keys)
    if type(obj) is not dict or set(obj) != {"schema_version", "scope", "release_authorizing", "required_event_fields", "forbidden_event_fields", "cases"}:
        raise ValueError("invalid top-level schema")
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise ValueError("invalid schema version")
    if obj["scope"] != "offline-denial-audit-privacy" or obj["release_authorizing"] is not False:
        raise ValueError("fixture must never authorize release")
    for field, expected in (("required_event_fields", REQUIRED), ("forbidden_event_fields", FORBIDDEN)):
        values = obj[field]
        if type(values) is not list or any(type(v) is not str for v in values) or len(values) != len(expected) or set(values) != expected:
            raise ValueError("invalid " + field)
    cases = obj["cases"]
    if type(cases) is not list or len(cases) != len(EXPECTED):
        raise ValueError("incorrect case count")
    found = set()
    for case in cases:
        if type(case) is not dict or set(case) != {"id", "condition", "expected_decision", "raw_sensitive_data_emitted"}:
            raise ValueError("invalid case schema")
        key = case["id"]
        if type(key) is not str or key not in EXPECTED or key in found or case["condition"] != EXPECTED[key]:
            raise ValueError("unknown/duplicate/mismatched case")
        if case["expected_decision"] != "DENY" or case["raw_sensitive_data_emitted"] is not False:
            raise ValueError("unsafe expected outcome")
        found.add(key)
    return True


if __name__ == "__main__":
    filename = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "scope_denial_audit_privacy_20261008.json"
    try:
        validate(filename.read_text(encoding="utf-8"))
    except (ValueError, TypeError, UnicodeError) as exc:
        print("INVALID offline fixture:", exc, file=sys.stderr)
        raise SystemExit(1)
    print("Offline denial-audit fixture schema valid; no runtime authorization attested.")
