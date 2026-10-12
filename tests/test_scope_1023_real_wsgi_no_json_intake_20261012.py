"""#1023 real in-process WSGI negative controls for absent JSON-grant intake.

These tests exercise the actual default LightUpWebApp + FormError boundary
without creating accounts, sessions, grants, targets, or dispatching tools.
They do not validate any installed proxy, Nginx, Gunicorn or production API.
"""
from __future__ import annotations

import io
import unittest
from unittest.mock import Mock

from lightup.webapp.app import LightUpWebApp
from lightup.webapp.security import WebSecurity


class ReadProbe(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_calls = 0

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        return super().read(size)


class NoJsonAuthorizationEnvelopeWSGI(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Mock(name="no_grant_store")
        self.app = LightUpWebApp(self.store, security=WebSecurity())

    def send(self, method: str, path: str, body: bytes = b"",
             content_type: str = "application/json", **headers: str):
        stream = ReadProbe(body)
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "HTTP_HOST": "localhost",
            "REMOTE_ADDR": "127.0.0.1",
            "wsgi.url_scheme": "http",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": content_type,
            "wsgi.input": stream,
        }
        environ.update(headers)
        recorded = []

        def start_response(status, response_headers):
            recorded.append((status, dict(response_headers)))

        data = b"".join(self.app(environ, start_response))
        self.assertEqual(len(recorded), 1)
        self.store.assert_not_called()
        self.assertFalse(self.store.mock_calls, "request must not read/write store")
        return recorded[0][0], recorded[0][1], data, stream

    def test_json_grant_post_rejected_before_body_read(self) -> None:
        status, headers, body, stream = self.send(
            "POST", "/engagements/synthetic/grants", b'{"approved":true}')
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(stream.read_calls, 0)
        self.assertIn(b"Invalid form request", body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_json_request_post_rejected_before_body_read(self) -> None:
        status, _, _, stream = self.send(
            "POST", "/portal/synthetic/requests", b'{"risk":5}',
            content_type="application/json; charset=utf-8")
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(stream.read_calls, 0)

    def test_no_new_json_authorization_endpoint(self) -> None:
        status, _, _, stream = self.send("GET", "/api/authorization-envelopes")
        self.assertEqual(status, "404 Not Found")
        self.assertEqual(stream.read_calls, 0)

    def test_unknown_json_post_is_not_an_authorization_intake(self) -> None:
        status, _, _, stream = self.send(
            "POST", "/api/authorization-envelopes", b'{"grant":"forged"}')
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(stream.read_calls, 0)

    def test_urlencoded_json_text_without_valid_fields_denied(self) -> None:
        status, _, _, stream = self.send(
            "POST", "/engagements/synthetic/grants",
            b'{"issuer":"forged"}', content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(stream.read_calls, 1)

    def test_form_shaped_forged_grant_requires_authenticated_operator(self) -> None:
        status, headers, _, stream = self.send(
            "POST", "/engagements/synthetic/grants",
            b"csrf=forged&approved=true", content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")
        self.assertEqual(stream.read_calls, 1)

    def test_oversize_form_refused_before_read(self) -> None:
        status, _, _, stream = self.send(
            "POST", "/engagements/synthetic/grants",
            b"", content_type="application/x-www-form-urlencoded",
            CONTENT_LENGTH="65537")
        self.assertEqual(status, "413 Payload Too Large")
        self.assertEqual(stream.read_calls, 0)

    def test_transfer_encoding_refused_before_read(self) -> None:
        status, _, _, stream = self.send(
            "POST", "/engagements/synthetic/grants",
            b"csrf=forged", content_type="application/x-www-form-urlencoded",
            HTTP_TRANSFER_ENCODING="chunked")
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(stream.read_calls, 0)


if __name__ == "__main__":
    unittest.main()
