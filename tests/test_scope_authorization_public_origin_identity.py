from __future__ import annotations

import unittest

from lightup.webapp.security import WebSecurity


class SameTextOrigin(str):
    pass


class DriftingOrigin(str):
    def __new__(
        cls,
        stored: str,
        first_origin: str,
        later_origin: str,
    ):
        obj = str.__new__(cls, stored)
        obj._first_origin = first_origin
        obj._later_origin = later_origin
        obj._lstrip_calls = 0
        return obj

    def lstrip(self, chars=None):
        self._lstrip_calls += 1
        if self._lstrip_calls == 1:
            return self._first_origin
        return self._later_origin


class PublicOriginIdentityTests(unittest.TestCase):
    def test_exact_https_public_origin_remains_valid(self) -> None:
        security = WebSecurity(
            public_origin="https://lightup.example",
            trusted_proxy_ip="127.0.0.1",
        )

        self.assertTrue(security.production)
        self.assertEqual(security.public_origin, "https://lightup.example")

    def test_exact_http_public_origin_remains_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            WebSecurity(
                public_origin="http://lightup.example",
                trusted_proxy_ip="127.0.0.1",
            )

    def test_same_text_origin_subclass_is_not_canonical_config(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "public_origin.*exact.*string|exact.*string.*public_origin",
        ):
            WebSecurity(
                public_origin=SameTextOrigin("https://lightup.example"),
                trusted_proxy_ip="127.0.0.1",
            )

    def test_stateful_origin_subclass_cannot_change_trust_after_admission(self) -> None:
        drifting = DriftingOrigin(
            "https://lightup.example",
            "https://lightup.example",
            "https://evil.example",
        )

        with self.assertRaisesRegex(
            ValueError,
            "public_origin.*exact.*string|exact.*string.*public_origin",
        ):
            WebSecurity(
                public_origin=drifting,
                trusted_proxy_ip="127.0.0.1",
            )


if __name__ == "__main__":
    unittest.main()
