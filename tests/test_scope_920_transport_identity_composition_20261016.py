"""Cross-contract #920 WebSecurity transport identity acceptance (synthetic/offline).

Only exact-built-in configuration success and fail-closed rejection controls:
issue #918 tests the proxy object, issue #919 tests the origin object. This
composition does not patch or substitute the #202 WebSecurity source owner.
No listener, network I/O, target interaction, customer data, or credentials.
"""
import unittest

from lightup.webapp.security import RequestRejected, WebSecurity


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
                    self.gate.validate(self.request(
                        REQUEST_METHOD="POST",
                        HTTP_ORIGIN="https://lightup.example.test",
                        **override,
                    ))

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
