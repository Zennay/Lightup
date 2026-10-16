"""#920 current-main exact-source WebSecurity ingress acceptance (offline only).

Distinct from pinned owner #202 acceptance PR #1478. Never confers authority.
All request data fictional, no network listener or target interaction.
"""
import unittest
from unittest.mock import Mock

from lightup.webapp import create_app
from lightup.webapp.security import RequestRejected, WebSecurity


ORIGIN = "https://lightup.example.test"
UNTRUSTED = "203.0.113.19"


class SameTextOrigin(str):
    pass


class CallerEqualityProxy(str):
    """Fictional untrusted config can override peer identity equality."""

    def __eq__(self, other):
        return other in ("127.0.0.1", UNTRUSTED)

    def __ne__(self, other):
        return not self.__eq__(other)


def request(**kwargs):
    value = {
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_HOST": "lightup.example.test",
        "HTTP_X_FORWARDED_PROTO": "https",
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/login",
    }
    value.update(kwargs)
    return value


def invoke(app, environ):
    receipt = {}
    body = b"".join(app(environ, lambda status, headers: receipt.update(
        status=status, headers=dict(headers))))
    return receipt, body


class CurrentMainTransportIdentityTest(unittest.TestCase):
    def setUp(self):
        self.gate = WebSecurity(ORIGIN, "127.0.0.1")

    def test_positive_exact_builtin_production_configuration_and_request(self):
        self.assertIs(type(self.gate.public_origin), str)
        self.assertIs(type(self.gate.trusted_proxy_ip), str)
        self.gate.validate(request())
        self.gate.validate(request(HTTP_HOST="LIGHTUP.EXAMPLE.TEST:443"))

    def test_exact_builtin_ipv6_proxy_keeps_peer_identity(self):
        gate = WebSecurity(ORIGIN, "::1")
        gate.validate(request(REMOTE_ADDR="::1"))
        for remote in ("127.0.0.1", UNTRUSTED, "[::1]"):
            with self.subTest(remote=remote), self.assertRaises(RequestRejected):
                gate.validate(request(REMOTE_ADDR=remote))

    def test_untrusted_peer_not_overridden_by_forwarded_metadata(self):
        for headers in (
            {"HTTP_X_FORWARDED_FOR": "127.0.0.1"},
            {"HTTP_FORWARDED": "for=127.0.0.1"},
            {"HTTP_X_FORWARDED_HOST": "lightup.example.test"},
            {},
        ):
            with self.subTest(headers=headers), self.assertRaises(RequestRejected):
                self.gate.validate(request(REMOTE_ADDR=UNTRUSTED, **headers))

    def test_host_and_https_are_independent_required_conditions(self):
        for data in (
            {"HTTP_HOST": "untrusted.example.test"},
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_X_FORWARDED_PROTO": "https,http"},
            {"HTTP_HOST": "lightup.example.test:444"},
        ):
            with self.subTest(data=data), self.assertRaises(RequestRejected):
                self.gate.validate(request(**data))

    def test_post_origin_cannot_override_untrusted_peer(self):
        self.gate.validate(request(
            REQUEST_METHOD="POST", HTTP_ORIGIN=ORIGIN,
        ))
        for data in (
            {"REMOTE_ADDR": UNTRUSTED},
            {"HTTP_ORIGIN": "https://untrusted.example.test"},
            {"HTTP_SEC_FETCH_SITE": "cross-site"},
        ):
            with self.subTest(data=data), self.assertRaises(RequestRejected):
                envelope = request(REQUEST_METHOD="POST", HTTP_ORIGIN=ORIGIN)
                envelope.update(data)
                self.gate.validate(envelope)

    def test_actual_wsgi_canonical_login_response(self):
        result, body = invoke(create_app(Mock(), self.gate), request())
        self.assertEqual(result["status"], "200 OK")
        self.assertIsInstance(body, bytes)

    def test_actual_wsgi_plain_remote_denied_before_store_or_post_body(self):
        store, stream = Mock(), Mock()
        app = create_app(store, self.gate)
        result, body = invoke(app, request(
            REMOTE_ADDR=UNTRUSTED, REQUEST_METHOD="POST", HTTP_ORIGIN=ORIGIN,
            CONTENT_LENGTH="0", **{"wsgi.input": stream},
        ))
        self.assertEqual(result["status"], "403 Forbidden")
        self.assertEqual(result["headers"]["Cache-Control"], "no-store")
        stream.read.assert_not_called()
        store.assert_not_called()
        self.assertIsInstance(body, bytes)

    @unittest.expectedFailure
    def test_red_nonbuiltin_trusted_proxy_rejected_at_constructor(self):
        with self.assertRaises(ValueError):
            WebSecurity(ORIGIN, CallerEqualityProxy("127.0.0.1"))

    @unittest.expectedFailure
    def test_red_nonbuiltin_origin_rejected_at_constructor(self):
        with self.assertRaises(ValueError):
            WebSecurity(SameTextOrigin(ORIGIN), "127.0.0.1")

    @unittest.expectedFailure
    def test_red_untrusted_peer_cannot_pass_polymorphic_config_equality(self):
        gate = WebSecurity(ORIGIN, CallerEqualityProxy("127.0.0.1"))
        with self.assertRaises(RequestRejected):
            gate.validate(request(REMOTE_ADDR=UNTRUSTED))

    @unittest.expectedFailure
    def test_red_actual_wsgi_rejects_polymorphic_proxy_peer_before_dispatch(self):
        gate = WebSecurity(ORIGIN, CallerEqualityProxy("127.0.0.1"))
        result, _ = invoke(create_app(Mock(), gate), request(REMOTE_ADDR=UNTRUSTED))
        self.assertEqual(result["status"], "403 Forbidden")


if __name__ == "__main__":
    unittest.main()
