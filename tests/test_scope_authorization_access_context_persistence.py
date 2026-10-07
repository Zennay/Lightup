from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lightup.domain import DomainStore, Role


class _ForgedOperatorRole:
    value = "operator"


class AccessContextPersistenceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "domain.db"
        self.store = DomainStore(self.db_path)
        operator = self.store.bootstrap_operator(
            "operator@lightup.test",
            "Operator",
            "correct-horse-battery",
        )
        self.operator = self.store.context_for_user(operator.user_id)

    def tearDown(self):
        self.tmp.cleanup()

    def _user_count(self, email: str) -> int:
        with sqlite3.connect(self.db_path) as con:
            row = con.execute("SELECT COUNT(*) FROM users WHERE email=?", (email,)).fetchone()
        assert row is not None
        return int(row[0])

    def test_create_user_rejects_forged_operator_role_before_persistence(self):
        client = self.store.create_client(self.operator, "Role Intake Client")
        before = self._user_count("forged-role@acme.test")

        with self.assertRaisesRegex(ValueError, "role must be a Role member"):
            self.store.create_user(
                self.operator,
                "forged-role@acme.test",
                "Forged Role",
                _ForgedOperatorRole(),  # type: ignore[arg-type]
                client.client_id,
            )

        self.assertEqual(self._user_count("forged-role@acme.test"), before)

    def test_create_user_rejects_noncanonical_client_selector_before_persistence(self):
        client = self.store.create_client(self.operator, "Selector Intake Client")
        before = self._user_count("bad-selector@acme.test")

        with self.assertRaisesRegex(ValueError, "client_id must be canonical"):
            self.store.create_user(
                self.operator,
                "bad-selector@acme.test",
                "Bad Selector",
                Role.CLIENT_ADMIN,
                " " + client.client_id,
            )

        self.assertEqual(self._user_count("bad-selector@acme.test"), before)

    def test_corrupt_persisted_identity_invalidates_existing_session(self):
        client = self.store.create_client(self.operator, "Session Client")
        user = self.store.create_user(
            self.operator,
            "session-admin@acme.test",
            "Session Admin",
            Role.CLIENT_ADMIN,
            client.client_id,
        )
        token, _csrf = self.store.create_session(user.user_id)
        self.assertIsNotNone(self.store.session_context(token))

        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE users SET client_id=? WHERE user_id=?",
                (" " + client.client_id, user.user_id),
            )

        # Durable identity corruption must become unauthenticated state rather
        # than bubbling a ValueError through the web authorization boundary.
        self.assertIsNone(self.store.session_context(token))

    def test_corrupt_persisted_client_identity_cannot_reconstruct_context(self):
        client = self.store.create_client(self.operator, "Acme BV")
        user = self.store.create_user(
            self.operator,
            "admin@acme.test",
            "Admin",
            Role.CLIENT_ADMIN,
            client.client_id,
        )

        canonical = self.store.context_for_user(user.user_id)
        self.assertEqual(canonical.client_id, client.client_id)

        # Simulate durable corruption outside the validated write path. A later
        # session/context read must fail closed rather than normalize it.
        with sqlite3.connect(self.db_path) as con:
            con.execute(
                "UPDATE users SET client_id=? WHERE user_id=?",
                (" " + client.client_id, user.user_id),
            )

        with self.assertRaisesRegex(ValueError, "canonical client_id"):
            self.store.context_for_user(user.user_id)


if __name__ == "__main__":
    unittest.main()
