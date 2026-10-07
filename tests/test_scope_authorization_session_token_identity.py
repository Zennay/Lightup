from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lightup.domain import DomainStore


class _EncodeSpoofingToken(str):
    """String whose visible identity differs from the bytes it hashes as."""

    def __new__(cls, visible_value: str, encoded_value: str):
        value = super().__new__(cls, visible_value)
        value._encoded_value = encoded_value
        return value

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        return self._encoded_value.encode(encoding, errors)


class SessionTokenIdentityBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.operator = self.store.bootstrap_operator(
            "session-boundary@lightup.test",
            "Session Boundary",
            "correct-horse-battery",
        )
        self.token, self.csrf = self.store.create_session(self.operator.user_id)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _assert_rejected_lookup(self, token: str) -> None:
        try:
            resolved = self.store.session_context(token)
        except (TypeError, ValueError):
            return
        self.assertIsNone(resolved)

    def test_exact_live_token_and_plain_forged_controls(self) -> None:
        resolved = self.store.session_context(self.token)
        self.assertIsNotNone(resolved)
        context, csrf = resolved
        self.assertEqual(context.user_id, self.operator.user_id)
        self.assertEqual(csrf, self.csrf)
        self.assertIsNone(self.store.session_context("plain-forged-session-token"))

    def test_foreign_string_subclass_cannot_encode_as_live_token(self) -> None:
        spoofed = _EncodeSpoofingToken(
            "attacker-controlled-visible-token",
            self.token,
        )

        self._assert_rejected_lookup(spoofed)

        # Rejection is state-atomic: the canonical session remains valid.
        resolved = self.store.session_context(self.token)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0].user_id, self.operator.user_id)

    def test_matching_text_string_subclass_is_still_noncanonical(self) -> None:
        spoofed = _EncodeSpoofingToken(self.token, self.token)

        self._assert_rejected_lookup(spoofed)

        # Exact built-in token identity remains the only accepted representation.
        self.assertIsNotNone(self.store.session_context(self.token))

    def test_polymorphic_revocation_cannot_delete_live_session(self) -> None:
        spoofed = _EncodeSpoofingToken(
            "different-visible-token",
            self.token,
        )

        try:
            self.store.revoke_session(spoofed)
        except (TypeError, ValueError):
            pass

        self.assertIsNotNone(self.store.session_context(self.token))


if __name__ == "__main__":
    unittest.main()
