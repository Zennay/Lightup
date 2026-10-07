from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import AccessContext, DomainStore, Role


class _PasswordText(str):
    """String subclass used to prove exact built-in password typing."""


class _EncodeSpoofPassword(str):
    def __new__(cls, visible: str, encoded_as: str):
        obj = super().__new__(cls, visible)
        obj._encoded_as = encoded_as
        return obj

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        return self._encoded_as.encode(encoding, errors)


class PasswordTextBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = AccessContext("bootstrap-op", Role.OPERATOR)
        self.user = self.store.create_user(
            self.operator,
            "operator@example.test",
            "Operator",
            Role.OPERATOR,
        )
        self.password = "correct horse battery staple"
        self.store.set_password(self.operator, self.user.user_id, self.password)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _credential_snapshot(self) -> tuple[bytes, bytes, str]:
        with self.store._connect() as con:
            row = con.execute(
                "SELECT salt,password_hash,updated_at FROM credentials WHERE user_id=?",
                (self.user.user_id,),
            ).fetchone()
        self.assertIsNotNone(row)
        return row["salt"], row["password_hash"], row["updated_at"]

    def _login_failure_snapshot(self):
        with self.store._connect() as con:
            row = con.execute(
                "SELECT failures,locked_until FROM login_failures WHERE email=?",
                (self.user.email,),
            ).fetchone()
        if row is None:
            return None
        return row["failures"], row["locked_until"]

    def test_exact_builtin_password_keeps_canonical_authentication_behavior(self) -> None:
        verified = self.store.verify_password(self.user.email, self.password)
        authenticated = self.store.authenticate(self.user.email, self.password)

        self.assertEqual(verified.user_id, self.user.user_id)
        self.assertEqual(authenticated.user_id, self.user.user_id)

    def test_same_text_string_subclass_is_rejected(self) -> None:
        subclass_password = _PasswordText(self.password)

        with self.assertRaises(ValueError):
            self.store.verify_password(self.user.email, subclass_password)

    def test_encode_spoof_cannot_authenticate_or_mutate_login_state(self) -> None:
        token, _ = self.store.create_session(self.user.user_id)
        with self.store._connect() as con:
            con.execute(
                "INSERT INTO login_failures(email,failures,locked_until) VALUES(?,?,?)",
                (self.user.email, 2, None),
            )
        before_failures = self._login_failure_snapshot()
        before_session = self.store.session_context(token)
        spoof = _EncodeSpoofPassword("visibly wrong password", self.password)

        with self.assertRaises(ValueError):
            self.store.authenticate(self.user.email, spoof)

        self.assertEqual(self._login_failure_snapshot(), before_failures)
        self.assertEqual(self.store.session_context(token), before_session)

    def test_polymorphic_password_update_cannot_replace_credential_or_revoke_session(self) -> None:
        token, _ = self.store.create_session(self.user.user_id)
        before_credential = self._credential_snapshot()
        before_session = self.store.session_context(token)
        spoof = _EncodeSpoofPassword(
            "visibly different replacement",
            "replacement password material",
        )

        with self.assertRaises(ValueError):
            self.store.set_password(self.operator, self.user.user_id, spoof)

        self.assertEqual(self._credential_snapshot(), before_credential)
        self.assertEqual(self.store.session_context(token), before_session)
        verified = self.store.verify_password(self.user.email, self.password)
        self.assertEqual(verified.user_id, self.user.user_id)


if __name__ == "__main__":
    unittest.main()
