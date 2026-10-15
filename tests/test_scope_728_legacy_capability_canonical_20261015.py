"""#728 -- exact built-in capability collection and entry identity, synthetic only.

An independent source-owner #122 acceptance suite: no handler, DNS or I/O.
expectedFailure denotes genuine installed-source authorization REDs, not a pass.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


HOST = "synthetic-canonical.example.test"
CAPABILITY = "fixture-header-read"
FORGED_CAPABILITY = "fixture-config-write"


class AlwaysMember(tuple):
    """A tuple subtype whose contains() lies about every membership check."""

    def __contains__(self, item):
        return True


class PretendCanonicalString(str):
    """A foreign text identity that lies during equality/membership checks."""

    def __eq__(self, other):
        return other == FORGED_CAPABILITY

    __hash__ = str.__hash__


def auth(capabilities):
    return Authorization(
        owner="fictional-capability-owner",
        reference="fixture-only-approval",
        assets=(HOST,),
        capabilities=capabilities,
    )


def authorized_gate():
    return ActivationGate(
        ScopePolicy(allow_private_lab=False, explicit_hosts=frozenset({HOST})),
        ActivationPolicy(
            mode=ActivationMode.AUTHORIZED,
            activation_reference="fixture-nonproduction",
        ),
    )


class LegacyCapabilityCanonicalIdentityAcceptance(unittest.TestCase):
    def test_exact_tuple_and_exact_builtin_string_work_as_before(self):
        authorization = auth((CAPABILITY,))
        self.assertIs(type(authorization.capabilities), tuple)
        self.assertTrue(all(type(x) is str for x in authorization.capabilities))
        self.assertTrue(authorization.allows_capability(CAPABILITY))
        permit = authorized_gate().issue(Target(HOST, authorization), CAPABILITY)
        self.assertEqual(permit.capability_id, CAPABILITY)

    def test_clean_tuple_denies_foreign_capability(self):
        authorization = auth((CAPABILITY,))
        self.assertFalse(authorization.allows_capability(FORGED_CAPABILITY))
        with self.assertRaises(PermissionError):
            authorized_gate().issue(Target(HOST, authorization), FORGED_CAPABILITY)

    def test_empty_collection_denies_both_values(self):
        authorization = auth(())
        for value in (CAPABILITY, FORGED_CAPABILITY):
            with self.subTest(capability=value):
                self.assertFalse(authorization.allows_capability(value))
                with self.assertRaises(PermissionError):
                    authorized_gate().issue(Target(HOST, authorization), value)

    def test_unknown_asset_cannot_mint_even_a_forged_capability(self):
        authorization = auth(AlwaysMember((CAPABILITY,)))
        with self.assertRaises(PermissionError):
            authorized_gate().issue(
                Target("unknown-canonical.example.test", authorization),
                FORGED_CAPABILITY,
            )

    def test_expired_grant_cannot_mint_with_forged_tuple(self):
        authorization = Authorization(
            owner="fictional-capability-owner",
            reference="fixture-expired",
            assets=(HOST,),
            capabilities=AlwaysMember((CAPABILITY,)),
            valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc),
        )
        with self.assertRaises(PermissionError):
            authorized_gate().issue(Target(HOST, authorization), FORGED_CAPABILITY)

    @unittest.expectedFailure  # open RED: tuple subclass retained; no canonical admission
    def test_tuple_subclass_must_not_be_retained_as_legacy_scope(self):
        authorization = auth(AlwaysMember((CAPABILITY,)))
        self.assertIs(type(authorization.capabilities), tuple)

    @unittest.expectedFailure  # open RED: __contains__ forges new authority
    def test_tuple_subclass_must_not_spoof_capability_membership(self):
        authorization = auth(AlwaysMember((CAPABILITY,)))
        self.assertFalse(authorization.allows_capability(FORGED_CAPABILITY))

    @unittest.expectedFailure  # open RED: forged membership reaches real ActivationGate
    def test_tuple_subclass_must_not_issue_foreign_capability_permit(self):
        authorization = auth(AlwaysMember((CAPABILITY,)))
        with self.assertRaises(PermissionError):
            authorized_gate().issue(Target(HOST, authorization), FORGED_CAPABILITY)

    @unittest.expectedFailure  # open RED: string subclass retained in source
    def test_capability_entries_must_be_exact_builtin_strings(self):
        authorization = auth((PretendCanonicalString("foreign-entry"),))
        self.assertTrue(all(type(item) is str for item in authorization.capabilities))

    @unittest.expectedFailure  # open RED: __eq__ spoofs canonical desired entry
    def test_string_subclass_must_not_spoof_allowlist_membership(self):
        authorization = auth((PretendCanonicalString("foreign-entry"),))
        self.assertFalse(authorization.allows_capability(FORGED_CAPABILITY))

    @unittest.expectedFailure  # open RED: equality spoof flows into permit issuance
    def test_string_subclass_must_not_issue_foreign_capability_permit(self):
        authorization = auth((PretendCanonicalString("foreign-entry"),))
        with self.assertRaises(PermissionError):
            authorized_gate().issue(Target(HOST, authorization), FORGED_CAPABILITY)


if __name__ == "__main__":
    unittest.main()
