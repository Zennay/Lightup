"""Exact installed-source witnesses for #725/#726/#728 (synthetic).

These ordinary passing tests establish the specific *unsafe behavior* that
separate expectedFailure denial tests identify. They are diagnostic-only and
MUST be retired or inverted when the source owner repairs these issues.
No handler or external target is ever invoked. A legacy ExecutionPermit is
a synthetic in-memory object, NOT permission to run a real capability.
"""
from __future__ import annotations

import unittest

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy


HOST = "synthetic-source-witness.example.test"
KNOWN = "fixture-read-headers"
FOREIGN = "fixture-change-config"


class SpuriousTupleMembership(tuple):
    def __contains__(self, item):
        return True


class SpuriousStringEquality(str):
    def __eq__(self, other):
        return other == FOREIGN

    __hash__ = str.__hash__


class SpuriousRequestEquality:
    def __eq__(self, other):
        return other == KNOWN


class RequestedStringSubclass(str):
    pass


def make_auth(capabilities):
    return Authorization(
        owner="fictional-authority",
        reference="review-only-fixture",
        assets=(HOST,),
        capabilities=capabilities,
    )


def issue(current_auth, requested):
    gate = ActivationGate(
        ScopePolicy(explicit_hosts=frozenset({HOST}), allow_private_lab=False),
        ActivationPolicy(
            mode=ActivationMode.AUTHORIZED,
            activation_reference="fixture-permit-review",
        ),
    )
    return gate.issue(Target(HOST, current_auth), requested)


class InstalledUnsafeCapabilityWitnesess(unittest.TestCase):
    def test_list_is_currently_retained_by_identity(self):
        supplied = [KNOWN]
        authorization = make_auth(supplied)
        self.assertIs(authorization.capabilities, supplied)

    def test_appending_caller_owned_list_currently_mints_extra_permit(self):
        supplied = [KNOWN]
        authorization = make_auth(supplied)
        self.assertFalse(authorization.allows_capability(FOREIGN))
        supplied.append(FOREIGN)
        self.assertTrue(authorization.allows_capability(FOREIGN))
        permit = issue(authorization, FOREIGN)
        self.assertEqual(permit.capability_id, FOREIGN)
        self.assertEqual(permit.target, HOST)

    def test_clearing_caller_owned_list_currently_removes_existing_permit(self):
        supplied = [KNOWN]
        authorization = make_auth(supplied)
        self.assertEqual(issue(authorization, KNOWN).capability_id, KNOWN)
        supplied.clear()
        self.assertFalse(authorization.allows_capability(KNOWN))
        with self.assertRaises(PermissionError):
            issue(authorization, KNOWN)

    def test_polymorphic_tuple_currently_retained_unmodified(self):
        supplied = SpuriousTupleMembership((KNOWN,))
        self.assertIs(make_auth(supplied).capabilities, supplied)

    def test_polymorphic_tuple_currently_mints_foreign_permit(self):
        supplied = SpuriousTupleMembership((KNOWN,))
        authorization = make_auth(supplied)
        self.assertNotIn(FOREIGN, tuple(supplied))
        permit = issue(authorization, FOREIGN)
        self.assertIs(type(permit.capability_id), str)
        self.assertEqual(permit.capability_id, FOREIGN)

    def test_polymorphic_entry_currently_mints_foreign_permit(self):
        foreign_entry = SpuriousStringEquality("other-unapproved-identity")
        self.assertNotEqual(str(foreign_entry), FOREIGN)
        authorization = make_auth((foreign_entry,))
        self.assertTrue(authorization.allows_capability(FOREIGN))
        permit = issue(authorization, FOREIGN)
        self.assertEqual(permit.capability_id, FOREIGN)

    def test_requested_str_subclass_currently_retained_in_permit(self):
        requested = RequestedStringSubclass(KNOWN)
        self.assertIsNot(type(requested), str)
        permit = issue(make_auth((KNOWN,)), requested)
        self.assertIs(permit.capability_id, requested)

    def test_nonstring_equality_spoof_currently_retained_in_permit(self):
        requested = SpuriousRequestEquality()
        permit = issue(make_auth((KNOWN,)), requested)
        self.assertIs(permit.capability_id, requested)
        self.assertIsNot(type(permit.capability_id), str)


if __name__ == "__main__":
    unittest.main()
