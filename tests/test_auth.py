from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role, RoleError


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = self.store.bootstrap_operator(
            "op@lightup.test", "Operator", "correct-horse-battery")
        self.op_ctx = self.store.context_for_user(self.operator.user_id)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bootstrap_only_once(self):
        with self.assertRaises(ValueError):
            self.store.bootstrap_operator("x@lightup.test", "X", "another-password")

    def test_password_verification(self):
        self.assertIsNotNone(
            self.store.verify_password("op@lightup.test", "correct-horse-battery"))
        self.assertIsNone(self.store.verify_password("op@lightup.test", "wrong-password"))
        self.assertIsNone(self.store.verify_password("ghost@lightup.test", "whatever-pass"))

    def test_short_passwords_rejected(self):
        with self.assertRaises(ValueError):
            self.store.set_password(self.op_ctx, self.operator.user_id, "short")

    def test_sessions_roundtrip_and_revocation(self):
        token, csrf = self.store.create_session(self.operator.user_id)
        resolved = self.store.session_context(token)
        self.assertIsNotNone(resolved)
        ctx, resolved_csrf = resolved
        self.assertEqual(ctx.user_id, self.operator.user_id)
        self.assertTrue(ctx.is_operator)
        self.assertEqual(resolved_csrf, csrf)
        self.store.revoke_session(token)
        self.assertIsNone(self.store.session_context(token))
        self.assertIsNone(self.store.session_context("forged-token"))
        self.assertIsNone(self.store.session_context(""))

    def test_password_change_invalidates_sessions(self):
        token, _ = self.store.create_session(self.operator.user_id)
        self.store.set_password(self.op_ctx, self.operator.user_id, "a-brand-new-password")
        self.assertIsNone(self.store.session_context(token))
        self.assertIsNotNone(
            self.store.verify_password("op@lightup.test", "a-brand-new-password"))

    def test_lockout_after_repeated_failures(self):
        from lightup.domain import AccountLockedError

        for _ in range(DomainStore.LOGIN_MAX_FAILURES):
            self.assertIsNone(self.store.authenticate("op@lightup.test", "wrong-password"))
        # Locked now — even the correct password is refused.
        with self.assertRaises(AccountLockedError):
            self.store.authenticate("op@lightup.test", "correct-horse-battery")
        # A successful sign-in (other account path) clears counters: create a
        # second user and show success resets failures.
        client = self.store.create_client(self.op_ctx, "Acme BV")
        user = self.store.create_user(self.op_ctx, "b@acme.test", "B",
                                      Role.CLIENT_ADMIN, client.client_id)
        self.store.set_password(self.op_ctx, user.user_id, "client-b-password")
        for _ in range(DomainStore.LOGIN_MAX_FAILURES - 1):
            self.assertIsNone(self.store.authenticate("b@acme.test", "nope-nope-nope"))
        self.assertIsNotNone(self.store.authenticate("b@acme.test", "client-b-password"))
        # Counter reset: new failures start from zero.
        self.assertIsNone(self.store.authenticate("b@acme.test", "nope-nope-nope"))

    def test_client_cannot_set_other_users_password(self):
        client = self.store.create_client(self.op_ctx, "Acme BV")
        user = self.store.create_user(self.op_ctx, "a@acme.test", "A",
                                      Role.CLIENT_ADMIN, client.client_id)
        client_ctx = AccessContext(user.user_id, Role.CLIENT_ADMIN, client.client_id)
        with self.assertRaises(RoleError):
            self.store.set_password(client_ctx, self.operator.user_id, "hijacked-pass")
        # But a user may change their own password.
        self.store.set_password(client_ctx, user.user_id, "my-own-password")
        self.assertIsNotNone(self.store.verify_password("a@acme.test", "my-own-password"))


if __name__ == "__main__":
    unittest.main()
