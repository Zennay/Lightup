"""Issue #919: independent, offline, *tests-only* WebSecurity origin-identity oracle.

Tests exercise the real, unmodified production WebSecurity constructor and validate().
The two expected failures document unresolved production behavior; they are not
successful security checks. No listener, DNS, target, or network I/O.
"""
import io
import unittest
from unittest.mock import Mock

from lightup.webapp import create_app
from lightup.webapp.security import RequestRejected, WebSecurity


TRUSTED = "lightup.example.test"
FOREIGN = "other.example.test"


def environ(host=TRUSTED, **changes):
    result = {
        "HTTP_HOST": host,
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_X_FORWARDED_PROTO": "https",
        "REQUEST_METHOD": "GET",
    }
    result.update(changes)
    return result


class SameTextOrigin(str):
    """Subclass has identical printable contents but noncanonical identity."""


class RewrittenOrigin(str):
    """Untrusted origin can change between constructor and request validation."""

    def __new__(cls, first, later):
        value = super().__new__(cls, first)
        value.calls = 0
        value.later = later
        return value

    def lstrip(self, chars=None):
        self.calls += 1
        # urllib.parse.urlsplit invokes str.lstrip; returning builtin str
        # makes the second parse unexpectedly point to a different host.
        return str(self) if self.calls == 1 else self.later


class PublicOriginIdentityIssue919(unittest.TestCase):
    @unittest.expectedFailure
    def test_red_same_text_string_subclass_denied_at_constructor(self):
        # Required #919 acceptance: reject all non-builtin string types.
        with self.assertRaises(ValueError):
            WebSecurity(SameTextOrigin("https://" + TRUSTED))

    @unittest.expectedFailure
    def test_red_stateful_subclass_cannot_repoint_host_between_requests(self):
        public = RewrittenOrigin("https://" + TRUSTED, "https://" + FOREIGN)
        security = WebSecurity(public)
        self.assertGreaterEqual(public.calls, 1)
        # Main currently reparses caller-supplied mutable-behavior object;
        # the foreign Host must never be trusted as the configured origin.
        with self.assertRaises(RequestRejected):
            security.validate(environ(FOREIGN))

    def test_canonical_builtin_string_preserves_stable_host(self):
        value = "https://" + TRUSTED
        self.assertIs(type(value), str)
        security = WebSecurity(value)
        security.validate(environ())
        security.validate(environ("LIGHTUP.EXAMPLE.TEST:443"))
        for other in (FOREIGN, TRUSTED + ".invalid", TRUSTED + ":444"):
            with self.subTest(other=other), self.assertRaises(RequestRejected):
                security.validate(environ(other))

    def test_forwarded_identity_is_not_host_authority(self):
        security = WebSecurity("https://" + TRUSTED)
        security.validate(environ(HTTP_X_FORWARDED_HOST=FOREIGN))
        with self.assertRaises(RequestRejected):
            security.validate(environ(FOREIGN, HTTP_X_FORWARDED_HOST=TRUSTED))

    def test_untrusted_peer_and_cleartext_fail_closed(self):
        security = WebSecurity("https://" + TRUSTED)
        for bad in (
            {"REMOTE_ADDR": "192.0.2.5"},
            {"REMOTE_ADDR": ""},
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_X_FORWARDED_PROTO": "https,http"},
        ):
            with self.subTest(bad=bad), self.assertRaises(RequestRejected):
                security.validate(environ(**bad))

    def test_post_origin_cannot_be_promoted_by_referer(self):
        security = WebSecurity("https://" + TRUSTED)
        with self.assertRaises(RequestRejected):
            security.validate(environ(
                REQUEST_METHOD="POST",
                HTTP_ORIGIN="https://" + FOREIGN,
                HTTP_REFERER="https://" + TRUSTED + "/login",
            ))
        security.validate(environ(
            REQUEST_METHOD="POST", HTTP_ORIGIN="https://" + TRUSTED,
        ))

    def test_malformed_builtin_origin_rejected(self):
        for value in ("", "http://" + TRUSTED, "https://" + TRUSTED + "/admin",
                      "https://" + TRUSTED + ":0", "https://" + TRUSTED + "?x=1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                WebSecurity(value)

    def test_non_string_origin_rejected(self):
        for value in (False, 17, b"https://lightup.example.test", [], {}):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                WebSecurity(value)

    def test_rejected_host_precedes_session_and_body_access(self):
        security = WebSecurity("https://" + TRUSTED)
        store, stream = Mock(), Mock()
        app = create_app(store, security)
        reply = {}
        data = b"".join(app(environ(
            FOREIGN, PATH_INFO="/login", REQUEST_METHOD="POST",
            HTTP_ORIGIN="https://" + FOREIGN, CONTENT_LENGTH="0",
            **{"wsgi.input": stream},
        ), lambda status, headers: reply.update(status=status, headers=dict(headers))))
        self.assertEqual(reply["status"], "403 Forbidden")
        self.assertEqual(reply["headers"]["Cache-Control"], "no-store")
        stream.read.assert_not_called()
        store.assert_not_called()
        self.assertIsInstance(data, bytes)

    def test_origin_errors_do_not_echo_foreign_host(self):
        security = WebSecurity("https://" + TRUSTED)
        with self.assertRaises(RequestRejected) as caught:
            security.validate(environ(FOREIGN))
        self.assertNotIn(FOREIGN, str(caught.exception))

    def test_development_loopback_behavior_is_not_implicitly_hardened(self):
        local = WebSecurity()
        local.validate({"HTTP_HOST": "localhost:8766"})
        local.validate({"HTTP_HOST": "127.0.0.1:8766"})
        with self.assertRaises(RequestRejected):
            local.validate({"HTTP_HOST": FOREIGN})


if __name__ == "__main__":
    unittest.main()
