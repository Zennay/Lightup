"""#920 current-main exact-source WebSecurity ingress acceptance (offline only).

Distinct from pinned owner #202 acceptance PR #1478. Never confers authority.
All request data fictional, no network listener or target interaction.
"""
import unittest
from unittest.mock import Mock, patch

from lightup.webapp import create_app
from lightup.webapp.production import create_production_app
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


class AllPeersProxy(str):
    """Fictional configuration equality object; NO permission authority."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


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

    def test_actual_production_factory_canonical_config_wires_exact_web_security(self):
        # A mock domain store keeps this real production factory fully offline.
        with patch("lightup.webapp.production.DomainStore") as store:
            app = create_production_app({
                "LIGHTUP_PUBLIC_ORIGIN": ORIGIN,
                "LIGHTUP_TRUSTED_PROXY_IP": "127.0.0.1",
                "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
            })
            store.assert_called_once_with("/tmp/lightup-920-fixture-only.db")
        self.assertIs(type(app.security.public_origin), str)
        self.assertIs(type(app.security.trusted_proxy_ip), str)
        app.security.validate(request())

    def test_actual_production_factory_bad_builtin_config_stops_before_store(self):
        for values in (
            {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.example.test"},
            {"LIGHTUP_TRUSTED_PROXY_IP": UNTRUSTED},
        ):
            with self.subTest(values=values):
                env = {
                    "LIGHTUP_PUBLIC_ORIGIN": ORIGIN,
                    "LIGHTUP_TRUSTED_PROXY_IP": "127.0.0.1",
                    "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
                }
                env.update(values)
                with patch("lightup.webapp.production.DomainStore") as store:
                    with self.assertRaises(ValueError):
                        create_production_app(env)
                    store.assert_not_called()

    @unittest.expectedFailure
    def test_red_production_factory_rejects_subclass_proxy_before_store(self):
        env = {
            "LIGHTUP_PUBLIC_ORIGIN": ORIGIN,
            "LIGHTUP_TRUSTED_PROXY_IP": CallerEqualityProxy("127.0.0.1"),
            "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
        }
        with patch("lightup.webapp.production.DomainStore") as store:
            with self.assertRaises(ValueError):
                create_production_app(env)
            store.assert_not_called()

    @unittest.expectedFailure
    def test_red_production_factory_rejects_subclass_origin_before_store(self):
        env = {
            "LIGHTUP_PUBLIC_ORIGIN": SameTextOrigin(ORIGIN),
            "LIGHTUP_TRUSTED_PROXY_IP": "127.0.0.1",
            "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
        }
        with patch("lightup.webapp.production.DomainStore") as store:
            with self.assertRaises(ValueError):
                create_production_app(env)
            store.assert_not_called()

    @unittest.expectedFailure
    def test_red_real_production_factory_wsgi_blocks_polymorphic_proxy_peer(self):
        env = {
            "LIGHTUP_PUBLIC_ORIGIN": ORIGIN,
            "LIGHTUP_TRUSTED_PROXY_IP": CallerEqualityProxy("127.0.0.1"),
            "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
        }
        with patch("lightup.webapp.production.DomainStore", return_value=Mock()) as store:
            try:
                app = create_production_app(env)
            except ValueError:
                # Best outcome: reject malformed configuration before store use.
                store.assert_not_called()
                return
            receipt, _ = invoke(app, request(REMOTE_ADDR=UNTRUSTED))
        self.assertEqual(receipt["status"], "403 Forbidden")

    def test_missing_real_socket_peer_is_rejected_before_wsgi_store(self):
        store = Mock()
        app = create_app(store, self.gate)
        request_without_peer = request()
        request_without_peer.pop("REMOTE_ADDR")
        response, body = invoke(app, request_without_peer)
        self.assertEqual(response["status"], "403 Forbidden")
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")
        store.assert_not_called()
        self.assertIsInstance(body, bytes)

    @unittest.expectedFailure
    def test_red_missing_peer_cannot_pass_caller_controlled_proxy_equality(self):
        try:
            gate = WebSecurity(ORIGIN, AllPeersProxy("127.0.0.1"))
        except ValueError:
            # Rejecting at configuration admission is preferable.
            return
        request_without_peer = request()
        request_without_peer.pop("REMOTE_ADDR")
        with self.assertRaises(RequestRejected):
            gate.validate(request_without_peer)

    @unittest.expectedFailure
    def test_red_production_factory_wsgi_requires_present_real_peer(self):
        env = {
            "LIGHTUP_PUBLIC_ORIGIN": ORIGIN,
            "LIGHTUP_TRUSTED_PROXY_IP": AllPeersProxy("127.0.0.1"),
            "LIGHTUP_DB": "/tmp/lightup-920-fixture-only.db",
        }
        request_without_peer = request()
        request_without_peer.pop("REMOTE_ADDR")
        with patch("lightup.webapp.production.DomainStore", return_value=Mock()) as store:
            try:
                app = create_production_app(env)
            except ValueError:
                store.assert_not_called()
                return
            response, _ = invoke(app, request_without_peer)
        self.assertEqual(response["status"], "403 Forbidden")

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
        try:
            gate = WebSecurity(ORIGIN, CallerEqualityProxy("127.0.0.1"))
        except ValueError:
            return
        with self.assertRaises(RequestRejected):
            gate.validate(request(REMOTE_ADDR=UNTRUSTED))

    @unittest.expectedFailure
    def test_red_actual_wsgi_rejects_polymorphic_proxy_peer_before_dispatch(self):
        try:
            gate = WebSecurity(ORIGIN, CallerEqualityProxy("127.0.0.1"))
        except ValueError:
            return
        result, _ = invoke(create_app(Mock(), gate), request(REMOTE_ADDR=UNTRUSTED))
        self.assertEqual(result["status"], "403 Forbidden")


if __name__ == "__main__":
    unittest.main()
