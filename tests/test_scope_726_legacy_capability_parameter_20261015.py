"""#726: actual legacy ActivationGate capability-id type boundary (synthetic RED).

Independent test-only acceptance pinned atop unchanged #122 owner source.
All target names and identities are fabricated. Never issues a real authority.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


HOST = "synthetic-parameter.example.test"
CANONICAL_ID = "fixture-service-header-read"
OTHER_ID = "fixture-service-config-write"


class TextSubclass(str):
    """Same contents, but not the producer-canonical built-in text type."""


class ArbitraryEqualityObject:
    """A non-string object that can compare equal to the exact allowlisted ID."""

    def __eq__(self, other):
        return other == CANONICAL_ID


def fixture_authorization():
    return Authorization(
        owner="fictional-capability-review",
        reference="fixture-nonproduction-reference",
        assets=(HOST,),
        capabilities=(CANONICAL_ID,),
    )


def gate(mode=ActivationMode.AUTHORIZED):
    return ActivationGate(
        ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset((HOST,))),
        ActivationPolicy(mode=mode, activation_reference="fixture-gate-review"),
    )


class LegacyActivationCapabilityParameterIdentity(unittest.TestCase):
    def test_canonical_exact_builtin_string_is_allowed_and_preserved(self):
        authorization = fixture_authorization()
        permit = gate().issue(Target(HOST, authorization), CANONICAL_ID)
        self.assertIs(type(permit.capability_id), str)
        self.assertEqual(permit.capability_id, CANONICAL_ID)

    def test_unrelated_exact_string_is_denied(self):
        with self.assertRaises(PermissionError):
            gate().issue(Target(HOST, fixture_authorization()), OTHER_ID)

    def test_missing_authorization_does_not_issue_even_for_allowed_text(self):
        with self.assertRaises(PermissionError):
            gate().issue(Target(HOST, None), CANONICAL_ID)

    def test_plan_only_denies_even_a_type_confused_requested_capability(self):
        with self.assertRaises(PermissionError):
            gate(ActivationMode.PLAN_ONLY).issue(
                Target(HOST, fixture_authorization()), ArbitraryEqualityObject()
            )

    def test_out_of_scope_target_denies_type_confused_requested_capability(self):
        with self.assertRaises(PermissionError):
            gate().issue(
                Target("unknown-parameter.example.test", fixture_authorization()),
                ArbitraryEqualityObject(),
            )

    def test_expired_authorization_denies_type_confused_requested_capability(self):
        authorization = Authorization(
            owner="fictional-capability-review",
            reference="fixture-expired",
            assets=(HOST,),
            capabilities=(CANONICAL_ID,),
            valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        with self.assertRaises(PermissionError):
            gate().issue(Target(HOST, authorization), ArbitraryEqualityObject())

    @unittest.expectedFailure  # source RED: subclass accepted by string membership
    def test_matching_text_subclass_must_not_issue_permit(self):
        with self.assertRaises(PermissionError):
            gate().issue(Target(HOST, fixture_authorization()), TextSubclass(CANONICAL_ID))

    @unittest.expectedFailure  # source RED: arbitrary equality object spoofs membership
    def test_equality_spoofing_nonstring_must_not_issue_permit(self):
        with self.assertRaises(PermissionError):
            gate().issue(Target(HOST, fixture_authorization()), ArbitraryEqualityObject())

    @unittest.expectedFailure  # source RED: permit preserves polymorphic caller identity
    def test_permit_must_not_contain_polymorphic_caller_capability(self):
        result = gate().issue(
            Target(HOST, fixture_authorization()), TextSubclass(CANONICAL_ID)
        )
        self.assertIs(type(result.capability_id), str)


if __name__ == "__main__":
    unittest.main()
