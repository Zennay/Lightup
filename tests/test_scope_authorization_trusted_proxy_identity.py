from __future__ import annotations

import unittest

from lightup.webapp.security import RequestRejected, WebSecurity


class SameTextProxy(str):
    pass


class EqualitySpoofingProxy(str):
    def __new__(cls, value: str, masquerades_as: str):
        obj = str.__new__(cls, value)
        obj._masquerades_as = masquerades_as
        return obj

    def __eq__(self, other: object) -> bool:
        return str(other) == self._masquerades_as

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self._masquerades_as)


def _production_environ(remote_addr: str) -> dict[str, str]:
    return {
        "REMOTE_ADDR": remote_addr,
        "HTTP_X_FORWARDED_PROTO": "https",
        "HTTP_HOST": "lightup.example",
        "REQUEST_METHOD": "GET",
    }


class TrustedProxyIdentityTests(unittest.TestCase):
    def test_exact_loopback_proxy_identity_remains_valid(self) -> None:
        for proxy in ("127.0.0.1", "::1"):
            with self.subTest(proxy=proxy):
                security = WebSecurity(
                    public_origin="https://lightup.example",
                    trusted_proxy_ip=proxy,
                )

                security.validate(_production_environ(proxy))

    def test_exact_remote_peer_remains_rejected(self) -> None:
        security = WebSecurity(
            public_origin="https://lightup.example",
            trusted_proxy_ip="127.0.0.1",
        )

        with self.assertRaises(RequestRejected):
            security.validate(_production_environ("203.0.113.5"))

    def test_same_text_proxy_string_subclass_is_not_canonical_config(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "trusted_proxy_ip.*exact.*string|exact.*string.*trusted_proxy_ip",
        ):
            WebSecurity(
                public_origin="https://lightup.example",
                trusted_proxy_ip=SameTextProxy("127.0.0.1"),
            )

    def test_equality_spoofing_proxy_cannot_trust_remote_socket_peer(self) -> None:
        forged = EqualitySpoofingProxy("127.0.0.1", "203.0.113.5")

        with self.assertRaisesRegex(
            ValueError,
            "trusted_proxy_ip.*exact.*string|exact.*string.*trusted_proxy_ip",
        ):
            WebSecurity(
                public_origin="https://lightup.example",
                trusted_proxy_ip=forged,
            )


if __name__ == "__main__":
    unittest.main()
