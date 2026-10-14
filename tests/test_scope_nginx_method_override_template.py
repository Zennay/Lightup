"""Offline acceptance for the shipped Nginx ingress template.

This inspects configuration text only. It never starts Nginx, Gunicorn or
a network listener and cannot attest an installed deployment.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path


TEMPLATE = Path(__file__).resolve().parents[1] / "deploy" / "nginx.conf.example"


class NginxMethodOverrideStripTests(unittest.TestCase):
    SPOOFABLE_HEADERS = (
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-Original-Method",
        "X-HTTP-Method",
    )

    @classmethod
    def setUpClass(cls):
        text = TEMPLATE.read_text(encoding="utf-8")
        marker = "    location / {"
        if text.count(marker) != 1:
            raise AssertionError("expected one canonical root proxy location")
        cls.template = text
        cls.root_proxy_block = text.split(marker, 1)[1].split("\n    }", 1)[0]

    def _header_values(self, name):
        pattern = re.compile(
            r"^\s*proxy_set_header\s+" + re.escape(name)
            + r"\s+([^;\n]+);\s*$",
            re.IGNORECASE | re.MULTILINE,
        )
        return pattern.findall(self.root_proxy_block)

    def test_four_common_method_override_headers_are_omitted(self):
        for name in self.SPOOFABLE_HEADERS:
            with self.subTest(header=name):
                self.assertEqual(self._header_values(name), ['""'])

    def test_guard_is_an_executable_nginx_directive_not_comment(self):
        for name in self.SPOOFABLE_HEADERS:
            with self.subTest(header=name):
                self.assertIn(
                    f'        proxy_set_header {name} "";',
                    self.root_proxy_block,
                )

    def test_nginx_does_not_rewrite_canonical_request_method(self):
        self.assertNotRegex(
            self.template,
            r"(?m)^\s*proxy_method\s+",
        )

    def test_forwarding_keeps_existing_explicit_origin_guards(self):
        self.assertIn(
            "proxy_pass http://127.0.0.1:8766;",
            self.root_proxy_block,
        )
        self.assertEqual(self._header_values("Host"), ["$http_host"])
        self.assertEqual(self._header_values("X-Forwarded-Proto"), ["https"])
        self.assertEqual(self._header_values("Forwarded"), ['""'])
        self.assertEqual(self._header_values("X-Forwarded-Host"), ['""'])


if __name__ == "__main__":
    unittest.main()
