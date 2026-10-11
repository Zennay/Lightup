"""Pure synthetic acceptance for optional post-render session snapshot helper.

No tokens, targets, network, scopes, grants, DB mutation, or real assessment.
"""
from __future__ import annotations

import unittest

from lightup.domain import AccessContext, Role
from lightup.webapp.checked_postrender_session_contract import (
    is_canonical_postrender_session,
)


class PoisonTuple(tuple):
    def __len__(self):
        raise AssertionError("untrusted subclass length was accessed")

    def __getitem__(self, key):
        raise AssertionError("untrusted subclass entry was accessed")


class PoisonStr(str):
    def __bool__(self):
        raise AssertionError("untrusted subclass truth value was accessed")


class PostrenderSessionContractW25Tests(unittest.TestCase):
    def setUp(self):
        self.expected = AccessContext(
            user_id="synthetic-user",
            role=Role.CLIENT_MEMBER,
            client_id="synthetic-tenant",
        )

    def test_canonical_tuple_allows_equivalent_persisted_identity(self):
        same = AccessContext("synthetic-user", Role.CLIENT_MEMBER, "synthetic-tenant")
        self.assertIsNot(same, self.expected)
        self.assertTrue(is_canonical_postrender_session((same, "csrf-token"), self.expected))

    def test_refuses_noncanonical_container_before_subclass_operations(self):
        for snapshot in (None, (), (self.expected,), (self.expected, "csrf", "extra"),
                         [self.expected, "csrf"], {"context": self.expected},
                         PoisonTuple((self.expected, "csrf")), object()):
            with self.subTest(container=type(snapshot).__name__):
                self.assertFalse(is_canonical_postrender_session(snapshot, self.expected))

    def test_refuses_missing_blank_nonstring_or_subclass_csrf(self):
        for csrf in (None, "", 12, False, b"csrf", PoisonStr("csrf")):
            with self.subTest(csrf_type=type(csrf).__name__, csrf_value=repr(csrf)):
                self.assertFalse(is_canonical_postrender_session((self.expected, csrf), self.expected))

    def test_refuses_changed_principal_role_or_tenant(self):
        others = (
            AccessContext("different-user", Role.CLIENT_MEMBER, "synthetic-tenant"),
            AccessContext("synthetic-user", Role.CLIENT_ADMIN, "synthetic-tenant"),
            AccessContext("synthetic-user", Role.CLIENT_MEMBER, "another-tenant"),
            AccessContext("synthetic-user", Role.OPERATOR),
        )
        for altered in others:
            with self.subTest(context=altered):
                self.assertFalse(is_canonical_postrender_session((altered, "csrf"), self.expected))

    def test_refuses_forged_or_missing_context_type(self):
        for context in (None, object(), "synthetic-user", {"user_id": "synthetic-user"}):
            with self.subTest(context_type=type(context).__name__):
                self.assertFalse(is_canonical_postrender_session((context, "csrf"), self.expected))
        self.assertFalse(is_canonical_postrender_session(
            (self.expected, "csrf"), object()
        ))

    def test_does_not_change_caller_supplied_identity_or_tuple(self):
        snapshot = (self.expected, "csrf")
        before = (self.expected.user_id, self.expected.role, self.expected.client_id)
        self.assertTrue(is_canonical_postrender_session(snapshot, self.expected))
        self.assertIs(snapshot[0], self.expected)
        self.assertEqual((self.expected.user_id, self.expected.role, self.expected.client_id), before)


if __name__ == "__main__":
    unittest.main()
