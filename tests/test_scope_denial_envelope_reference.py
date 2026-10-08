"""Pure offline acceptance reference for a bounded, non-authoritative denial envelope.

This deliberately does not import the production executor, issue grants, or contact
targets. A production implementation must be reviewed separately.
"""
import json
import unittest

_ALLOWED_REASONS = frozenset({"AUTHORIZATION_DENIED", "AUDIT_UNAVAILABLE"})
_MAX_EVENT_BYTES = 512


def denial_envelope(*, reason, correlation_id, untrusted_details=None):
    """Return only fixed code and a bounded ASCII-safe opaque correlation identifier."""
    if type(reason) is not str or reason not in _ALLOWED_REASONS:
        reason = "AUTHORIZATION_DENIED"
    if type(correlation_id) is not str or not (1 <= len(correlation_id) <= 64):
        correlation_id = "invalid"
    elif not all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in correlation_id):
        correlation_id = "invalid"
    # Intentionally never inspect/format/repr/serialize untrusted_details.
    record = {"category": reason, "correlation_id": correlation_id}
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=True)
    if len(serialized.encode("ascii")) > _MAX_EVENT_BYTES:
        raise AssertionError("bounded denial envelope exceeded maximum size")
    return record


class Poison:
    def __str__(self):
        raise AssertionError("Untrusted object must not be formatted")

    def __repr__(self):
        raise AssertionError("Untrusted object must not be represented")


class DenialEnvelopeReferenceTests(unittest.TestCase):
    def test_known_reason_is_retained(self):
        self.assertEqual(denial_envelope(reason="AUDIT_UNAVAILABLE", correlation_id="run_123"),
                         {"category": "AUDIT_UNAVAILABLE", "correlation_id": "run_123"})

    def test_untrusted_exception_and_secret_are_not_read_or_logged(self):
        record = denial_envelope(reason="AUTHORIZATION_DENIED", correlation_id="run-42",
                                 untrusted_details={"token": "secret-123", "exception": Poison()})
        self.assertNotIn("secret-123", json.dumps(record))
        self.assertNotIn("token", json.dumps(record))

    def test_freeform_reason_cannot_become_event_field(self):
        value = denial_envelope(reason="denied bearer-secret-123", correlation_id="run-42")
        self.assertEqual(value["category"], "AUTHORIZATION_DENIED")

    def test_untrusted_unicode_and_control_correlation_id_is_rejected(self):
        for candidate in ("run\nsecret", "run/asset", "é", "a" * 65, "", None, 42):
            with self.subTest(candidate=candidate):
                self.assertEqual(denial_envelope(reason="AUTHORIZATION_DENIED",
                                                  correlation_id=candidate)["correlation_id"], "invalid")

    def test_subclassed_identifiers_fail_closed(self):
        class SneakyStr(str):
            pass

        self.assertEqual(denial_envelope(reason=SneakyStr("AUDIT_UNAVAILABLE"),
                                         correlation_id=SneakyStr("run123")),
                         {"category": "AUTHORIZATION_DENIED", "correlation_id": "invalid"})

    def test_unbounded_untrusted_payload_does_not_expand_record(self):
        huge = "secret" * 100000
        record = denial_envelope(reason="AUTHORIZATION_DENIED", correlation_id="run_1",
                                 untrusted_details=huge)
        self.assertLessEqual(len(json.dumps(record).encode("utf-8")), _MAX_EVENT_BYTES)
        self.assertNotIn("secret", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
