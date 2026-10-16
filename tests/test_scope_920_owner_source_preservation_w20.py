"""Test-only source-owner preservation controls, no network or real grants."""
from __future__ import annotations

import unittest

from lightup.webapp.security import RequestRejected, WebSecurity


def _production(**changes: str) -> dict[str, str]:
    request = {
        "REQUEST_METHOD": "GET",
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_HOST": "lightup.example",
    }
    request.update(changes)
    return request


class WebSecuritySourcePreservationW20(unittest.TestCase):
    def setUp(self) -> None:
        self.production = WebSecurity(public_origin="https://lightup.example")

    def assertDenied(self, request: dict[str, str]) -> None:
        with self.assertRaises(RequestRejected):
            self.production.validate(request)

    def test_canonical_https_get_still_passes(self) -> None:
        self.production.validate(_production())

    def test_remote_peer_does_not_gain_proxy_trust(self) -> None:
        self.assertDenied(_production(REMOTE_ADDR="203.0.113.17"))

    def test_spoofed_proxy_cannot_make_synthetic_remote_peer_trusted(self) -> None:
        class _EqualitySpoofProxy(str):
            def __new__(cls, value: str, alias: str):
                item = str.__new__(cls, value)
                item.alias = alias
                return item

            def __eq__(self, other: object) -> bool:
                return str(other) == self.alias

            def __ne__(self, other: object) -> bool:
                return not self.__eq__(other)

            def __hash__(self) -> int:
                return hash(self.alias)

        forged = _EqualitySpoofProxy("127.0.0.1", "203.0.113.17")
        # Constructor denial is ideal; request denial is a secondary guard.
        # The original owner source satisfies neither: it wrongly permits
        # this *synthetic* remote peer with a malicious config object.
        with self.assertRaises((ValueError, RequestRejected)):
            security = WebSecurity(
                public_origin="https://lightup.example", trusted_proxy_ip=forged,
            )
            security.validate(_production(REMOTE_ADDR="203.0.113.17"))

    def test_forwarded_http_does_not_claim_https(self) -> None:
        self.assertDenied(_production(HTTP_X_FORWARDED_PROTO="http"))

    def test_forwarded_proto_missing_does_not_claim_https(self) -> None:
        request = _production()
        request.pop("HTTP_X_FORWARDED_PROTO")
        self.assertDenied(request)

    def test_wrong_host_is_denied(self) -> None:
        self.assertDenied(_production(HTTP_HOST="evil.example"))

    def test_cross_site_post_is_denied(self) -> None:
        self.assertDenied(_production(REQUEST_METHOD="POST", HTTP_SEC_FETCH_SITE="cross-site", HTTP_ORIGIN="https://lightup.example"))

    def test_valid_post_origin_still_passes(self) -> None:
        self.production.validate(_production(REQUEST_METHOD="POST", HTTP_ORIGIN="https://lightup.example"))

    def test_wrong_post_origin_is_denied(self) -> None:
        self.assertDenied(_production(REQUEST_METHOD="POST", HTTP_ORIGIN="https://evil.example"))

    def test_missing_post_origin_and_referer_are_denied(self) -> None:
        self.assertDenied(_production(REQUEST_METHOD="POST"))

    def test_same_origin_post_referer_still_passes(self) -> None:
        self.production.validate(_production(REQUEST_METHOD="POST", HTTP_REFERER="https://lightup.example/account"))

    def test_development_wsgi_no_socket_peer_still_passes(self) -> None:
        WebSecurity().validate({"REQUEST_METHOD": "GET", "HTTP_HOST": "localhost"})

    def test_development_remote_peer_stays_denied(self) -> None:
        with self.assertRaises(RequestRejected):
            WebSecurity().validate({"REMOTE_ADDR": "203.0.113.17", "HTTP_HOST": "localhost", "REQUEST_METHOD": "GET"})


if __name__ == "__main__":
    unittest.main()
