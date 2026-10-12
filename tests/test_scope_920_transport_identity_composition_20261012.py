"""#920: compose trusted-proxy and public-origin identity trust boundaries.

Pure in-process WebSecurity fixtures. Never opens a listener or emits requests.
The intentionally expected-failure case is NOT proof of a fixed ingress gate.
"""
from __future__ import annotations

import unittest

from lightup.webapp.security import RequestRejected, WebSecurity


class _CoercionProxy(str):
    """Stores a local IP but lies about equality to a remote peer."""

    def __new__(cls, value: str, spoofed_peer: str):
        result = str.__new__(cls, value)
        result._spoofed_peer = spoofed_peer
        return result

    def __eq__(self, other: object) -> bool:
        return str(other) == self._spoofed_peer

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)


class _StatefulOrigin(str):
    """Supplies different URL text across successive parsing operations."""

    def __new__(cls, good: str, altered: str):
        result = str.__new__(cls, good)
        result._altered = altered
        result._reads = 0
        return result

    def lstrip(self, chars=None):
        self._reads += 1
        return str(self) if self._reads == 1 else self._altered


def _production_environ(
    peer: str,
    host: str = "lightup.example",
    method: str = "GET",
    origin: str | None = None,
) -> dict[str, str]:
    environ = {
        "REMOTE_ADDR": peer,
        "HTTP_HOST": host,
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_X_FORWARDED_FOR": "127.0.0.1",
        "REQUEST_METHOD": method,
    }
    if origin is not None:
        environ["HTTP_ORIGIN"] = origin
    return environ


class CombinedWebTransportIdentityTests(unittest.TestCase):
    def test_canonical_proxy_origin_pair_allows_matching_https(self) -> None:
        security = WebSecurity(
            public_origin="https://lightup.example",
            trusted_proxy_ip="127.0.0.1",
        )
        security.validate(_production_environ("127.0.0.1"))
        security.validate(
            _production_environ(
                "127.0.0.1", method="POST", origin="https://lightup.example"
            )
        )

    def test_valid_proxy_pair_still_denies_foreign_peer_and_forged_headers(self) -> None:
        security = WebSecurity(
            public_origin="https://lightup.example",
            trusted_proxy_ip="127.0.0.1",
        )
        with self.assertRaises(RequestRejected):
            security.validate(_production_environ("203.0.113.5"))
        with self.assertRaises(RequestRejected):
            security.validate(_production_environ("127.0.0.1", host="outside.test"))

    def test_valid_peer_still_denies_cross_origin_post(self) -> None:
        security = WebSecurity(
            public_origin="https://lightup.example",
            trusted_proxy_ip="::1",
        )
        with self.assertRaises(RequestRejected):
            security.validate(
                _production_environ(
                    "::1", method="POST", origin="https://outside.test"
                )
            )

    @unittest.expectedFailure
    def test_combined_polymorphic_configuration_is_rejected_before_any_trust(self) -> None:
        # Both objects are exact-text lookalikes, but neither is an exact str.
        # A repaired owner implementation must reject *at construction*.
        proxy = _CoercionProxy("127.0.0.1", "203.0.113.5")
        origin = _StatefulOrigin("https://lightup.example", "https://outside.test")
        with self.assertRaises(ValueError):
            WebSecurity(
                public_origin=origin,
                trusted_proxy_ip=proxy,
            )


if __name__ == "__main__":
    unittest.main()
