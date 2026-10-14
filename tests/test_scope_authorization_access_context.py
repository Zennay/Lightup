from __future__ import annotations

import unittest

from lightup.domain import AccessContext, Role


class _SpoofedString(str):
    pass


class AccessContextAuthorizationBoundaryTests(unittest.TestCase):
    def test_canonical_operator_and_client_contexts_remain_valid(self):
        operator = AccessContext("operator-1", Role.OPERATOR)
        client = AccessContext("user-1", Role.CLIENT_ADMIN, "client-1")

        self.assertTrue(operator.is_operator)
        self.assertFalse(client.is_operator)
        self.assertEqual(client.resolve_client(None, "read"), "client-1")

    def test_role_must_be_an_exact_role_member(self):
        with self.assertRaisesRegex(ValueError, "role must be a Role member"):
            AccessContext("user-1", "client_admin", "client-1")  # type: ignore[arg-type]

    def test_user_id_must_be_exact_canonical_text(self):
        invalid_user_ids = (
            "",
            " user-1",
            "user-1 ",
            "user\x00-1",
            _SpoofedString("user-1"),
        )
        for user_id in invalid_user_ids:
            with self.subTest(user_id=repr(user_id)):
                with self.assertRaises(ValueError):
                    AccessContext(user_id, Role.OPERATOR)

    def test_client_id_must_be_exact_canonical_text_for_client_roles(self):
        invalid_client_ids = (
            None,
            "",
            " client-1",
            "client-1 ",
            "client\x00-1",
            _SpoofedString("client-1"),
        )
        for client_id in invalid_client_ids:
            with self.subTest(client_id=repr(client_id)):
                with self.assertRaises(ValueError):
                    AccessContext("user-1", Role.CLIENT_MEMBER, client_id)  # type: ignore[arg-type]

    def test_resolve_client_rejects_noncanonical_selector_identity(self):
        operator = AccessContext("operator-1", Role.OPERATOR)
        client = AccessContext("user-1", Role.CLIENT_ADMIN, "client-1")

        invalid = (
            "",
            " client-1",
            "client-1 ",
            "client\x00-1",
            _SpoofedString("client-1"),
        )
        for client_id in invalid:
            with self.subTest(client_id=repr(client_id)):
                with self.assertRaises(ValueError):
                    operator.resolve_client(client_id, "read")
                with self.assertRaises(ValueError):
                    client.resolve_client(client_id, "read")

    def test_operator_cannot_carry_client_identity(self):
        with self.assertRaisesRegex(ValueError, "operator contexts are not bound to a client"):
            AccessContext("operator-1", Role.OPERATOR, "client-1")


if __name__ == "__main__":
    unittest.main()
