"""Offline contract tests: HTTP Retry-After is transport metadata, never a grant.

Synthetic consistency is NOT issuer authentication or production permission.
No imports from production executor, sockets, DNS, or live targets.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class Evidence:
    tenant: object
    request: object
    asset: object
    capability: object
    revision: object
    current: object


def _identifier(value):
    return (
        type(value) is str and 0 < len(value) <= 128
        and value.isascii()
        and all(0x21 <= ord(char) <= 0x7e for char in value)
    )


def _revision(value):
    return type(value) is int and value > 0


def consistent_for_dispatch(grant, dispatch, retry_after=None):
    """Only synthetic *necessary* conditions, not sufficient authority.

    retry_after is intentionally never inspected: it cannot change the answer.
    Production MUST independently check authenticated issuer, consent, revocation,
    time, scope, risk, and active execution gate at actual dispatch.
    """
    if type(grant) is not Evidence or type(dispatch) is not Evidence:
        return False
    for key in ("tenant", "request", "asset", "capability"):
        left, right = getattr(grant, key), getattr(dispatch, key)
        if not _identifier(left) or not _identifier(right) or left != right:
            return False
    if not _revision(grant.revision) or not _revision(dispatch.revision):
        return False
    return (
        grant.revision == dispatch.revision
        and type(grant.current) is bool
        and type(dispatch.current) is bool
        and grant.current is True
        and dispatch.current is True
    )


VALID = Evidence("tenant-a", "req-1", "asset-1", "headers", 2, True)


class RetryAfterNonauthorityTests(unittest.TestCase):
    def test_matching_reference_is_only_necessary_consistency(self):
        self.assertTrue(consistent_for_dispatch(VALID, VALID))

    def test_retry_after_does_not_create_missing_consent(self):
        denied = dataclasses.replace(VALID, current=False)
        for value in ("0", "120", "Fri, 09 Oct 2026 12:00:00 GMT", None):
            with self.subTest(value=value):
                self.assertFalse(consistent_for_dispatch(denied, VALID, value))

    def test_retry_after_cannot_restore_revoked_dispatch(self):
        denied = dataclasses.replace(VALID, current=False)
        self.assertFalse(consistent_for_dispatch(VALID, denied, "0"))

    def test_retry_after_cannot_override_revision_mismatch(self):
        self.assertFalse(consistent_for_dispatch(VALID, dataclasses.replace(VALID, revision=3), "0"))

    def test_retry_after_cannot_authorize_other_tenant(self):
        self.assertFalse(consistent_for_dispatch(VALID, dataclasses.replace(VALID, tenant="tenant-b"), "0"))

    def test_retry_after_cannot_authorize_other_request(self):
        self.assertFalse(consistent_for_dispatch(VALID, dataclasses.replace(VALID, request="req-2"), "0"))

    def test_retry_after_cannot_authorize_other_asset(self):
        self.assertFalse(consistent_for_dispatch(VALID, dataclasses.replace(VALID, asset="asset-2"), "0"))

    def test_retry_after_cannot_authorize_other_capability(self):
        self.assertFalse(consistent_for_dispatch(VALID, dataclasses.replace(VALID, capability="tls"), "0"))

    def test_retry_after_is_ignored_even_if_malicious_object(self):
        class Hostile:
            def __str__(self):
                raise AssertionError("Retry-After must not be parsed for authorization")
            def __bool__(self):
                raise AssertionError("Retry-After must not be checked for authorization")
        self.assertTrue(consistent_for_dispatch(VALID, VALID, Hostile()))

    def test_matching_malformed_identity_is_rejected(self):
        for bad in ("asset\n1", "asset 1", "", "asset\x001", "é"):
            with self.subTest(bad=repr(bad)):
                malformed = dataclasses.replace(VALID, asset=bad)
                self.assertFalse(consistent_for_dispatch(malformed, malformed, "0"))

    def test_boolean_or_float_revision_is_rejected(self):
        for value in (True, 2.0, 0, -1):
            with self.subTest(value=value):
                bad = dataclasses.replace(VALID, revision=value)
                self.assertFalse(consistent_for_dispatch(bad, bad, "0"))

    def test_truthy_current_is_not_true(self):
        for value in (1, "true", [True]):
            with self.subTest(value=repr(value)):
                bad = dataclasses.replace(VALID, current=value)
                self.assertFalse(consistent_for_dispatch(bad, VALID, "0"))

    def test_polymorphic_identity_cannot_be_authority(self):
        class StringLike(str):
            pass
        bad = dataclasses.replace(VALID, tenant=StringLike("tenant-a"))
        self.assertFalse(consistent_for_dispatch(bad, bad, "0"))

    def test_polymorphic_evidence_is_rejected(self):
        class Derived(Evidence):
            pass
        self.assertFalse(consistent_for_dispatch(Derived(**dataclasses.asdict(VALID)), VALID, "0"))

    def test_invalid_grant_fields_are_rejected_even_when_dispatch_matches(self):
        cases = (
            ("tenant", "other-tenant"),
            ("request", "other-request"),
            ("asset", "other-asset"),
            ("capability", "other-capability"),
            ("revision", 99),
            ("current", False),
        )
        for key, value in cases:
            with self.subTest(field=key):
                changed = dataclasses.replace(VALID, **{key: value})
                self.assertFalse(consistent_for_dispatch(changed, VALID, "0"))

    def test_retry_after_transport_variations_never_modify_decision(self):
        # Retry hints include malformed, unbounded and forged objects.
        hints = ("", "0", "-1", "999999999999999999999",
                 "Fri, 09 Oct 2026 12:00:00 GMT", "not-a-date",
                 {"status": 202, "retry_after": 0}, ["0"], False, 0)
        denied = dataclasses.replace(VALID, current=False)
        for hint in hints:
            with self.subTest(hint=repr(hint)):
                self.assertTrue(consistent_for_dispatch(VALID, VALID, hint))
                self.assertFalse(consistent_for_dispatch(VALID, denied, hint))

    def test_matching_str_subclasses_cannot_mint_authority(self):
        class Label(str):
            pass
        for field in ("tenant", "request", "asset", "capability"):
            with self.subTest(field=field):
                invalid = dataclasses.replace(VALID, **{field: Label(getattr(VALID, field))})
                self.assertFalse(consistent_for_dispatch(invalid, invalid, "0"))

    def test_zero_or_noncanonical_grant_revision_denied(self):
        for revision in (0, -2, True, 2.0, "2"):
            with self.subTest(revision=repr(revision)):
                grant = dataclasses.replace(VALID, revision=revision)
                self.assertFalse(consistent_for_dispatch(grant, VALID, "0"))

    def test_reference_has_no_input_mutation(self):
        before = dataclasses.asdict(VALID)
        consistent_for_dispatch(VALID, VALID, "0")
        self.assertEqual(dataclasses.asdict(VALID), before)


if __name__ == "__main__":
    unittest.main()
