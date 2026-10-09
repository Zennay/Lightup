"""Offline reference: tracing context is correlation data, never authorization.

This intentionally does not patch the production dispatcher or issue grants.
No DNS, network, filesystem writes, or target I/O.
"""
import unittest
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestEnvelope:
    target: str
    capability: str
    traceparent: object = None
    tracestate: object = None
    baggage: object = None
    verified_grant: object = None


def reference_admit(envelope, verified_grant_ids=frozenset()):
    """Only trusted, out-of-band grant identities can authorize dispatch."""
    if type(envelope) is not RequestEnvelope:
        return False
    if type(envelope.target) is not str or not envelope.target:
        return False
    if type(envelope.capability) is not str or not envelope.capability:
        return False
    grant = envelope.verified_grant
    return type(grant) is str and grant in verified_grant_ids


class TraceContextNonAuthorityTests(unittest.TestCase):
    def test_traceparent_cannot_mint_a_grant(self):
        for context in (
            "00-" + "a" * 32 + "-" + "b" * 16 + "-01",
            "grant=approved",
            "owner-approved",
            "",
            None,
        ):
            with self.subTest(context=context):
                self.assertFalse(reference_admit(RequestEnvelope(
                    "lab.example.invalid", "web-baseline", traceparent=context
                )))

    def test_tracestate_and_baggage_cannot_mint_grants(self):
        for state in ("tenant=approved", "vendor=admin", "grant=trusted"):
            with self.subTest(state=state):
                self.assertFalse(reference_admit(RequestEnvelope(
                    "lab.example.invalid", "web-baseline",
                    tracestate=state, baggage="authorization=approved"
                )))

    def test_conflicting_tracing_metadata_does_not_override_verified_grant(self):
        expected = frozenset({"verified-fixture-only"})
        for trace in ("unauthorized", "revoked", "other-client", None):
            with self.subTest(trace=trace):
                self.assertTrue(reference_admit(RequestEnvelope(
                    "lab.example.invalid", "web-baseline", traceparent=trace,
                    verified_grant="verified-fixture-only"
                ), expected))

    def test_revoked_grant_is_denied_even_with_valid_trace_context(self):
        self.assertFalse(reference_admit(RequestEnvelope(
            "lab.example.invalid", "web-baseline",
            traceparent="00-" + "a" * 32 + "-" + "b" * 16 + "-01",
            verified_grant="revoked-fixture"
        ), frozenset({"different-active-fixture"})))

    def test_hostile_tracing_objects_are_not_inspected(self):
        class Poison:
            def __str__(self):
                raise AssertionError("tracing metadata must not be coerced")
            def __bool__(self):
                raise AssertionError("tracing metadata must not be evaluated")
            def __iter__(self):
                raise AssertionError("tracing metadata must not be traversed")
        poison = Poison()
        self.assertFalse(reference_admit(RequestEnvelope(
            "lab.example.invalid", "web-baseline",
            traceparent=poison, tracestate=poison, baggage=poison
        )))
        self.assertTrue(reference_admit(RequestEnvelope(
            "lab.example.invalid", "web-baseline",
            traceparent=poison, tracestate=poison, baggage=poison,
            verified_grant="trusted-fixture"
        ), frozenset({"trusted-fixture"})))

    def test_truthy_or_subclass_grant_ids_are_denied(self):
        class GrantAlias(str):
            pass
        allowed = frozenset({"trusted-fixture"})
        for grant in (True, 1, GrantAlias("trusted-fixture"), [], None):
            with self.subTest(grant_type=type(grant).__name__):
                self.assertFalse(reference_admit(RequestEnvelope(
                    "lab.example.invalid", "web-baseline", verified_grant=grant
                ), allowed))


if __name__ == "__main__":
    unittest.main()
