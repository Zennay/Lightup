"""Independent #918 trusted-proxy exact-identity acceptance (offline synthetic).

This test file does not change the production WebSecurity source owner #202.
The deliberate XFAILs prove noncanonical proxy objects are admitted/retained;
they do not claim live network-origin spoofing has been demonstrated.
"""
import unittest
from unittest.mock import Mock

from lightup.webapp import create_app
from lightup.webapp.security import RequestRejected, WebSecurity


ORIGIN = "https://lightup.example.test"
REMOTE = "203.0.113.19"


def request(**updates):
    return {
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_HOST": "lightup.example.test",
        "HTTP_X_FORWARDED_PROTO": "https",
        "REQUEST_METHOD": "GET",
        **updates,
    }


class SameTextProxy(str):
    """Same contents but untrusted runtime identity."""


class SpoofEqualityProxy(str):
    """Demonstrate why caller-controlled comparison methods are dangerous."""

    def __eq__(self, other):
        return other in ("127.0.0.1", REMOTE)

    def __ne__(self, other):
        return not self.__eq__(other)


class TrustedProxyIdentityIssue918(unittest.TestCase):
    @unittest.expectedFailure
    def test_red_same_text_proxy_subclass_denied_before_ip_parsing(self):
        with self.assertRaises(ValueError):
            WebSecurity(ORIGIN, SameTextProxy("127.0.0.1"))

    @unittest.expectedFailure
    def test_red_polymorphic_proxy_value_not_retained_as_trust_anchor(self):
        spoofed = SpoofEqualityProxy("127.0.0.1")
        security = WebSecurity(ORIGIN, spoofed)
        # The deployment reference must be a trusted builtin exact string;
        # the current class stores the arbitrary caller-supplied instance.
        self.assertIs(type(security.trusted_proxy_ip), str)

    def test_builtin_ipv4_proxy_allows_exact_peer_only(self):
        security = WebSecurity(ORIGIN, "127.0.0.1")
        self.assertIs(type(security.trusted_proxy_ip), str)
        security.validate(request())
        for peer in ("127.0.0.2", REMOTE, "", "::1", "127.0.0.1,203.0.113.19"):
            with self.subTest(peer=peer), self.assertRaises(RequestRejected):
                security.validate(request(REMOTE_ADDR=peer))

    def test_builtin_ipv6_loopback_has_exact_peer_identity(self):
        security = WebSecurity(ORIGIN, "::1")
        security.validate(request(REMOTE_ADDR="::1"))
        for peer in ("127.0.0.1", "[::1]", REMOTE):
            with self.subTest(peer=peer), self.assertRaises(RequestRejected):
                security.validate(request(REMOTE_ADDR=peer))

    def test_forwarded_for_cannot_relabel_real_socket_peer(self):
        security = WebSecurity(ORIGIN)
        security.validate(request(HTTP_X_FORWARDED_FOR=REMOTE))
        with self.assertRaises(RequestRejected):
            security.validate(request(REMOTE_ADDR=REMOTE, HTTP_X_FORWARDED_FOR="127.0.0.1"))

    def test_forwarded_host_does_not_override_exact_socket_peer(self):
        security = WebSecurity(ORIGIN)
        with self.assertRaises(RequestRejected):
            security.validate(request(REMOTE_ADDR=REMOTE, HTTP_X_FORWARDED_HOST="lightup.example.test"))

    def test_builtin_proxy_non_loopback_or_invalid_ip_rejected(self):
        for address in (REMOTE, "0.0.0.0", "::", "localhost", "127.0.0.1/32", ""):
            with self.subTest(address=address), self.assertRaises(ValueError):
                WebSecurity(ORIGIN, address)

    def test_non_string_proxy_never_becomes_transport_authority(self):
        for value in ([], {}, True, 123, b"127.0.0.1"):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                WebSecurity(ORIGIN, value)

    def test_missing_proxy_identity_cannot_accept_post_origin(self):
        security = WebSecurity(ORIGIN)
        with self.assertRaises(RequestRejected):
            security.validate(request(REMOTE_ADDR="", REQUEST_METHOD="POST", HTTP_ORIGIN=ORIGIN))

    def test_reject_message_does_not_leak_untrusted_ip(self):
        security = WebSecurity(ORIGIN)
        with self.assertRaises(RequestRejected) as error:
            security.validate(request(REMOTE_ADDR=REMOTE))
        self.assertNotIn(REMOTE, str(error.exception))

    def test_real_wsgi_rejects_untrusted_proxy_before_store_or_body_read(self):
        security = WebSecurity(ORIGIN)
        store, stream = Mock(), Mock()
        app = create_app(store, security)
        response = {}
        body = b"".join(app(request(
            REMOTE_ADDR=REMOTE, REQUEST_METHOD="POST", PATH_INFO="/login",
            HTTP_ORIGIN=ORIGIN, CONTENT_LENGTH="0",
            **{"wsgi.input": stream},
        ), lambda status, headers: response.update(status=status, headers=dict(headers))))
        self.assertEqual(response["status"], "403 Forbidden")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        stream.read.assert_not_called()
        store.assert_not_called()
        self.assertIsInstance(body, bytes)


if __name__ == "__main__":
    unittest.main()
