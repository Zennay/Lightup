"""Offline acceptance model: denial responses must not reveal tenant existence.

This is NOT a production endpoint test or authorization implementation.
"""
import unittest
from dataclasses import dataclass

PUBLIC_DENIAL = (403, "authorization_denied", "Request is not authorized")
SECRET_FIELDS = ("tenant_id", "grant_id", "reviewer", "internal_reason", "account_email")


@dataclass(frozen=True)
class TenantDecision:
    exists: bool
    caller_matches: bool
    active_grant: bool
    scope_matches: bool


def reference_response(decision: TenantDecision):
    """Only fully authorized requests get a success marker; all denials indistinguishable."""
    if type(decision) is not TenantDecision:
        return PUBLIC_DENIAL
    fields = (decision.exists, decision.caller_matches, decision.active_grant, decision.scope_matches)
    if not all(type(field) is bool for field in fields):
        return PUBLIC_DENIAL
    if all(fields):
        return (200, "accepted", "Request accepted")
    return PUBLIC_DENIAL


class TenantDenialIndistinguishabilityTests(unittest.TestCase):
    def test_unknown_and_foreign_tenant_same_denial(self):
        unknown = TenantDecision(False, False, False, False)
        foreign = TenantDecision(True, False, True, True)
        self.assertEqual(reference_response(unknown), reference_response(foreign))

    def test_inactive_and_out_of_scope_same_denial(self):
        expired = TenantDecision(True, True, False, True)
        out_of_scope = TenantDecision(True, True, True, False)
        self.assertEqual(reference_response(expired), reference_response(out_of_scope))

    def test_all_denied_combinations_identical(self):
        from itertools import product
        responses = {
            reference_response(TenantDecision(*flags))
            for flags in product((False, True), repeat=4)
            if not all(flags)
        }
        self.assertEqual(responses, {PUBLIC_DENIAL})

    def test_exact_booleans_required(self):
        for bad in (1, 0, "true", None, [], object()):
            with self.subTest(value=repr(bad)):
                self.assertEqual(
                    reference_response(TenantDecision(True, True, bad, True)),
                    PUBLIC_DENIAL,
                )

    def test_malformed_each_authorization_flag_denied(self):
        from dataclasses import replace
        valid = TenantDecision(True, True, True, True)
        for field in ("exists", "caller_matches", "active_grant", "scope_matches"):
            for bad in (1, "yes", None):
                with self.subTest(field=field, bad=repr(bad)):
                    self.assertEqual(
                        reference_response(replace(valid, **{field: bad})),
                        PUBLIC_DENIAL,
                    )

    def test_dataclass_subclass_cannot_claim_authority(self):
        class ImpersonatedDecision(TenantDecision):
            pass

        self.assertEqual(
            reference_response(ImpersonatedDecision(True, True, True, True)),
            PUBLIC_DENIAL,
        )

    def test_denial_input_unchanged(self):
        from dataclasses import fields
        candidate = TenantDecision(True, False, True, False)
        before = tuple(getattr(candidate, field.name) for field in fields(candidate))
        self.assertEqual(reference_response(candidate), PUBLIC_DENIAL)
        self.assertEqual(
            tuple(getattr(candidate, field.name) for field in fields(candidate)),
            before,
        )

    def test_invalid_container_denied(self):
        self.assertEqual(reference_response({"exists": True}), PUBLIC_DENIAL)

    def test_only_full_authorization_is_positive(self):
        self.assertEqual(
            reference_response(TenantDecision(True, True, True, True))[0], 200
        )

    def test_public_denial_contains_no_private_identifiers(self):
        serialized = repr(PUBLIC_DENIAL).lower()
        for field in SECRET_FIELDS:
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)


if __name__ == "__main__":
    unittest.main()
