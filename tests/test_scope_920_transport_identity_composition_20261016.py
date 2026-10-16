"""Cross-contract #920 WebSecurity transport identity acceptance (synthetic/offline).

Only exact-built-in configuration success and fail-closed rejection controls:
issue #918 tests the proxy object, issue #919 tests the origin object. This
composition does not patch or substitute the #202 WebSecurity source owner.
No listener, network I/O, target interaction, customer data, or credentials.
"""
import unittest
from unittest.mock import Mock

from lightup.webapp import create_app
from lightup.webapp.security import RequestRejected, WebSecurity



class PolymorphicProxyIdentity(str):
    """Fictional caller-owned proxy object; must not be a trust anchor."""

    def __eq__(self, other):
        return other in ("127.0.0.1", "203.0.113.19")

    def __ne__(self, other):
        return not self.__eq__(other)


class TransportIdentityCompositionTests(unittest.TestCase):
    def setUp(self):
        self.gate = WebSecurity(
            public_origin="https://lightup.example.test",
            trusted_proxy_ip="127.0.0.1",
        )

    @staticmethod
    def request(**changes):
        request = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_HOST": "lightup.example.test",
            "HTTP_X_FORWARDED_PROTO": "https",
            "REQUEST_METHOD": "GET",
        }
        request.update(changes)
        return request

    def test_canonical_exact_builtins_accept_together(self):
        self.assertTrue(self.gate.production)
        self.assertIs(type(self.gate.public_origin), str)
        self.assertIs(type(self.gate.trusted_proxy_ip), str)
        self.gate.validate(self.request())

    def test_proxy_rejection_cannot_be_cured_by_matching_origin(self):
        with self.assertRaises(RequestRejected):
            self.gate.validate(self.request(REMOTE_ADDR="203.0.113.77"))

    def test_origin_rejection_cannot_be_cured_by_trusted_proxy(self):
        with self.assertRaises(RequestRejected):
            self.gate.validate(self.request(HTTP_HOST="untrusted.example.test"))

    def test_untrusted_forwarded_for_does_not_choose_socket_peer(self):
        request = self.request(
            REMOTE_ADDR="203.0.113.77",
            HTTP_X_FORWARDED_FOR="127.0.0.1",
            HTTP_FORWARDED="for=127.0.0.1",
        )
        with self.assertRaises(RequestRejected):
            self.gate.validate(request)

    def test_forwarded_host_does_not_override_http_host(self):
        with self.assertRaises(RequestRejected):
            self.gate.validate(self.request(
                HTTP_HOST="untrusted.example.test",
                HTTP_X_FORWARDED_HOST="lightup.example.test",
            ))

    def test_both_checks_hold_for_post_requests(self):
        self.gate.validate(self.request(
            REQUEST_METHOD="POST",
            HTTP_ORIGIN="https://lightup.example.test",
        ))
        for override in (
            {"HTTP_ORIGIN": "https://untrusted.example.test"},
            {"REMOTE_ADDR": "203.0.113.77"},
            {"HTTP_HOST": "untrusted.example.test"},
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_SEC_FETCH_SITE": "cross-site"},
        ):
            with self.subTest(override=override):
                with self.assertRaises(RequestRejected):
                    request = self.request(
                        REQUEST_METHOD="POST",
                        HTTP_ORIGIN="https://lightup.example.test",
                    )
                    request.update(override)
                    self.gate.validate(request)


    def test_exhaustive_offline_joint_transport_truth_table(self):
        # 5 x 3 x 3 = 45 independent synthetic input envelopes.
        # A good Host must not cure a bad peer or scheme, and vice versa.
        for peer in ("127.0.0.1", "127.0.0.2", "203.0.113.77", "", None):
            for host in ("lightup.example.test", "untrusted.example.test",
                         "lightup.example.test.."):
                for scheme in ("https", "http", None):
                    with self.subTest(peer=peer, host=host, scheme=scheme):
                        request = self.request(
                            REMOTE_ADDR=peer, HTTP_HOST=host,
                            HTTP_X_FORWARDED_PROTO=scheme,
                        )
                        accepted = (peer == "127.0.0.1" and
                                    host == "lightup.example.test" and
                                    scheme == "https")
                        if accepted:
                            self.gate.validate(request)
                        else:
                            with self.assertRaises(RequestRejected):
                                self.gate.validate(request)

    def test_transport_validation_does_not_mutate_caller_metadata(self):
        for request in (
            self.request(),
            self.request(REMOTE_ADDR="203.0.113.77"),
            self.request(HTTP_HOST="untrusted.example.test"),
        ):
            with self.subTest(request=request):
                before = request.copy()
                try:
                    self.gate.validate(request)
                except RequestRejected:
                    pass
                self.assertEqual(request, before)

    @unittest.expectedFailure
    def test_red_caller_proxy_equality_cannot_admit_untrusted_peer(self):
        # This is an offline source-RED, not an external connection attempt.
        # Before any request checks the constructor MUST reject polymorphic
        # identity. The original source currently retains the object instead.
        gate = WebSecurity(
            public_origin="https://lightup.example.test",
            trusted_proxy_ip=PolymorphicProxyIdentity("127.0.0.1"),
        )
        with self.assertRaises(RequestRejected):
            gate.validate(self.request(REMOTE_ADDR="203.0.113.19"))

    @unittest.expectedFailure
    def test_red_real_wsgi_login_route_rejects_polymorphic_remote_peer(self):
        # Exercise the installed WSGI request path entirely in process.
        # A 200 login response would prove transport admission was bypassed,
        # not an authenticated session, privilege escalation or real exploit.
        gate = WebSecurity(
            public_origin="https://lightup.example.test",
            trusted_proxy_ip=PolymorphicProxyIdentity("127.0.0.1"),
        )
        app = create_app(Mock(), gate)
        response = {}
        body = b"".join(app(
            self.request(REMOTE_ADDR="203.0.113.19", PATH_INFO="/login"),
            lambda status, headers: response.update(
                status=status, headers=dict(headers)),
        ))
        self.assertEqual(response["status"], "403 Forbidden")
        self.assertIn(b"Request rejected", body)

    def test_canonical_proxy_real_wsgi_login_is_reachable_without_session(self):
        # Positive control ensures the same WSGI route is genuinely exercised.
        app = create_app(Mock(), self.gate)
        response = {}
        body = b"".join(app(
            self.request(PATH_INFO="/login"),
            lambda status, headers: response.update(
                status=status, headers=dict(headers)),
        ))
        self.assertEqual(response["status"], "200 OK")
        self.assertIsInstance(body, bytes)

    def test_untrusted_peer_real_wsgi_denied_before_body_or_store(self):
        # Negative control proves the WSGI source-RED does not merely fail
        # because of an invalid app fixture or a missing response callback.
        store, stream = Mock(), Mock()
        app = create_app(store, self.gate)
        response = {}
        body = b"".join(app(
            self.request(
                PATH_INFO="/login", REQUEST_METHOD="POST",
                REMOTE_ADDR="203.0.113.19",
                HTTP_ORIGIN="https://lightup.example.test",
                CONTENT_LENGTH="0", **{"wsgi.input": stream},
            ),
            lambda status, headers: response.update(
                status=status, headers=dict(headers)),
        ))
        self.assertEqual(response["status"], "403 Forbidden")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        stream.read.assert_not_called()
        store.assert_not_called()
        self.assertIsInstance(body, bytes)

    def test_invalid_production_settings_refuse_at_constructor(self):
        for kwargs in (
            {"public_origin": "http://lightup.example.test"},
            {"public_origin": "https://lightup.example.test",
             "trusted_proxy_ip": "203.0.113.77"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    WebSecurity(**kwargs)


if __name__ == "__main__":
    unittest.main()
