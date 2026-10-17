"""Regression contract for duplicate LightUp session cookie admission (issue #686).

Owns tests only: production web authentication is owned by PR #182.
All state uses a disposable SQLite DB, synthetic identities and sessions.
Source RED cases deliberately remain expectedFailure until the source owner
implements fail-closed admission ahead of DomainStore.session_context().
"""
from __future__ import annotations

import io
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.app import ANONYMOUS


class DuplicateSessionCookieAcceptance(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "domain.db")
        self.app = create_app(self.store)
        operator = self.store.bootstrap_operator(
            "scope686-op@lightup.test", "Fictional operator", "fictional-password"
        )
        op_context = self.store.context_for_user(operator.user_id)
        client = self.store.create_client(op_context, "Synthetic tenant")
        member = self.store.create_user(
            op_context, "scope686-client@lightup.test", "Fictional client",
            Role.CLIENT_ADMIN, client.client_id
        )
        self.operator_token, self.operator_csrf = self.store.create_session(operator.user_id)
        self.client_token, self.client_csrf = self.store.create_session(member.user_id)
        self.client_id = client.client_id

    def _auth(self, header: str):
        return self.app._authenticate({"HTTP_COOKIE": header})

    def _wsgi(self, header: str, *, path: str = "/"):
        state = {}
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
            "HTTP_COOKIE": header,
        }
        chunks = self.app(environ, lambda status, headers: state.update(
            status=status, headers=dict(headers)))
        return state["status"], state["headers"], b"".join(chunks)

    def _assert_ambiguous_denied_prelookup(self, header: str) -> None:
        # Both sessions must remain valid after a failed request; do NOT
        # conflate admission denial with a revoke/logout action.
        with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
            auth = self._auth(header)
            lookup.assert_not_called()
        self.assertFalse(auth.signed_in)
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_no_session_cookie_is_anonymous_without_lookup(self):
        for header in ("", "theme=dark", "lightup_session_extra=not-a-session"):
            with self.subTest(header=header):
                with patch.object(self.store, "session_context") as lookup:
                    self.assertFalse(self._auth(header).signed_in)
                    lookup.assert_not_called()

    def test_single_operator_session_remains_authorized(self):
        for header in (
            f"lightup_session={self.operator_token}",
            f"theme=dark; lightup_session={self.operator_token}; lang=nl",
        ):
            with self.subTest(extra_cookies=("theme" in header)):
                auth = self._auth(header)
                self.assertTrue(auth.signed_in)
                self.assertTrue(auth.is_operator)
                self.assertEqual(auth.csrf, self.operator_csrf)

    def test_single_client_session_retains_tenant(self):
        header = f"pref=compact; lightup_session={self.client_token}"
        auth = self._auth(header)
        self.assertTrue(auth.signed_in)
        self.assertFalse(auth.is_operator)
        self.assertEqual(auth.context.client_id, self.client_id)
        self.assertEqual(auth.csrf, self.client_csrf)

    def test_invalid_single_session_stays_anonymous(self):
        auth = self._auth("theme=dark; lightup_session=not-a-real-session")
        self.assertFalse(auth.signed_in)

    def test_wsgi_operator_single_cookie_control(self):
        status, _, body = self._wsgi(f"lightup_session={self.operator_token}")
        self.assertEqual(status, "200 OK")
        self.assertIn(b"Active testing", body)

    def test_wsgi_client_operator_isolation_control(self):
        status, headers, _ = self._wsgi(
            f"lightup_session={self.client_token}")
        self.assertEqual(status, "403 Forbidden")
        self.assertNotIn("Set-Cookie", headers)

    @unittest.expectedFailure
    def test_red_duplicate_identical_operator_token_prelookup(self):
        token = self.operator_token
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={token}; lightup_session={token}")

    @unittest.expectedFailure
    def test_red_duplicate_operator_then_client_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={self.operator_token}; lightup_session={self.client_token}")

    @unittest.expectedFailure
    def test_red_duplicate_client_then_operator_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session={self.client_token}; lightup_session={self.operator_token}")

    @unittest.expectedFailure
    def test_red_duplicate_surrounded_by_unrelated_cookies(self):
        self._assert_ambiguous_denied_prelookup(
            "theme=dark; lightup_session=" + self.operator_token
            + "; lang=nl; lightup_session=" + self.client_token + "; end=1")

    @unittest.expectedFailure
    def test_red_duplicate_valid_after_invalid_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            f"lightup_session=invalid; lightup_session={self.operator_token}")

    @unittest.expectedFailure
    def test_red_wsgi_duplicate_must_not_gain_operator_access(self):
        status, headers, _ = self._wsgi(
            f"lightup_session={self.client_token}; lightup_session={self.operator_token}")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers.get("Location"), "/login")
        self.assertNotIn("Set-Cookie", headers)
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))


    @unittest.expectedFailure
    def test_red_duplicate_cannot_logout_either_session(self):
        # Block revocation even on a vulnerable source so the regression
        # itself never destroys a valid session.
        form = ("csrf=" + self.operator_csrf).encode("ascii")
        env = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/logout",
            "CONTENT_LENGTH": str(len(form)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(form),
            "HTTP_COOKIE": "lightup_session=" + self.client_token
            + "; lightup_session=" + self.operator_token,
        }
        out = {}
        with patch.object(self.store, "revoke_session") as revoke:
            with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
                b"".join(self.app(env, lambda s, h: out.update(status=s, headers=dict(h))))
                lookup.assert_not_called()
                revoke.assert_not_called()
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))
        self.assertNotIn("Set-Cookie", out["headers"])

    @unittest.expectedFailure
    def test_red_duplicate_cannot_create_client(self):
        form = b"name=ShouldNotExist"
        env = {
            "REQUEST_METHOD": "POST", "PATH_INFO": "/clients",
            "CONTENT_LENGTH": str(len(form)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(form),
            "HTTP_COOKIE": "lightup_session=" + self.client_token
            + "; lightup_session=" + self.operator_token,
        }
        out = {}
        with patch.object(self.store, "create_client") as create_client:
            with patch.object(self.store, "session_context", wraps=self.store.session_context) as lookup:
                b"".join(self.app(env, lambda s, h: out.update(status=s, headers=dict(h))))
                lookup.assert_not_called()
                create_client.assert_not_called()
        self.assertNotIn("Set-Cookie", out["headers"])
        self.assertIsNotNone(self.store.session_context(self.operator_token))
        self.assertIsNotNone(self.store.session_context(self.client_token))


    @unittest.expectedFailure
    def test_red_duplicate_three_cookie_variants_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            "theme=dark; lightup_session=" + self.operator_token
            + "; lightup_session=" + self.client_token
            + "; lightup_session=" + self.operator_token)

    @unittest.expectedFailure
    def test_red_duplicate_mixed_spaces_prelookup(self):
        self._assert_ambiguous_denied_prelookup(
            "lightup_session = " + self.operator_token
            + " ; theme=ok; lightup_session=" + self.client_token)

    def test_single_session_with_repeated_unrelated_cookie_is_valid(self):
        header = ("theme=one; lightup_session=" + self.operator_token
                  + "; theme=two; lightup_session_extra=irrelevant")
        auth = self._auth(header)
        self.assertTrue(auth.signed_in)
        self.assertTrue(auth.is_operator)

    def test_owner_fix_rehearsal_turns_ten_original_source_reds_green(self):
        # A *test-local witness only*, not a production parser or a wired
        # middleware: reproduces the narrowly specified duplicate count
        # admission invariant for the exact synthetic cookie shapes below.
        raw_authenticate = self.app._authenticate

        def illustrative_prelookup_gate(environ):
            raw = environ.get("HTTP_COOKIE", "")
            if isinstance(raw, str):
                count = sum(
                    segment.partition("=")[0].strip() == "lightup_session"
                    for segment in raw.split(";")
                )
                if count > 1:
                    return ANONYMOUS
            return raw_authenticate(environ)

        exact_red_cases = (
            "test_red_duplicate_identical_operator_token_prelookup",
            "test_red_duplicate_operator_then_client_prelookup",
            "test_red_duplicate_client_then_operator_prelookup",
            "test_red_duplicate_surrounded_by_unrelated_cookies",
            "test_red_duplicate_valid_after_invalid_prelookup",
            "test_red_wsgi_duplicate_must_not_gain_operator_access",
            "test_red_duplicate_cannot_logout_either_session",
            "test_red_duplicate_cannot_create_client",
            "test_red_duplicate_three_cookie_variants_prelookup",
            "test_red_duplicate_mixed_spaces_prelookup",
        )
        with patch.object(self.app, "_authenticate", side_effect=illustrative_prelookup_gate):
            for name in exact_red_cases:
                with self.subTest(red_source_witness=name):
                    # Direct invocation intentionally bypasses the unittest
                    # expectedFailure runner: any assertion now fails normally.
                    getattr(self, name)()
            self.test_single_operator_session_remains_authorized()
            self.test_single_client_session_retains_tenant()
            self.test_single_session_with_repeated_unrelated_cookie_is_valid()

            # Deterministic adversarial batches; no network, no real clients.
            rng = random.Random(686)
            for index in range(128):
                sessions = rng.choices((self.operator_token, self.client_token), k=rng.randint(2, 5))
                segments = ["lightup_session=" + token for token in sessions]
                segments.extend("pref=" + str(i) for i in range(rng.randint(0, 4)))
                rng.shuffle(segments)
                with self.subTest(iteration=index, count=len(sessions)):
                    self._assert_ambiguous_denied_prelookup("; ".join(segments))

        # A values-only de-duplication fix is *not* sufficient when the
        # duplicated credential bytes are identical.
        def inadequate_values_only_gate(environ):
            raw = environ.get("HTTP_COOKIE", "")
            values = [
                fragment.partition("=")[2]
                for fragment in raw.split(";")
                if fragment.partition("=")[0].strip() == "lightup_session"
            ]
            if len(set(values)) > 1:
                return ANONYMOUS
            return raw_authenticate(environ)

        with patch.object(self.app, "_authenticate", side_effect=inadequate_values_only_gate):
            with self.assertRaises(AssertionError):
                self.test_red_duplicate_identical_operator_token_prelookup()


if __name__ == "__main__":
    unittest.main()
