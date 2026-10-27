"""Non-network synthetic HTTP/1.1 framing controls for LightUp #1161."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from scope_1161_http1_framing_fixture_gate import (  # noqa: E402
    MAX_HEADER_FIELDS, MAX_SYNTHETIC_BODY, accepts_synthetic_http1_fixture,
)

GET = b"GET /health HTTP/1.1"
POST = b"POST /clients HTTP/1.1"
HOST = b"Host: localhost"
FORM = b"Content-Type: application/x-www-form-urlencoded"


def request(start=GET, headers=(HOST,), body=b""):
    return b"\r\n".join((start, *headers)) + b"\r\n\r\n" + body


def posted(body=b"x=1", *, extra=(), length=None):
    if length is None:
        length = str(len(body)).encode("ascii")
    return request(POST, (HOST, FORM, b"Content-Length: " + length, *extra), body)


class SyntheticHTTPFramingPreflightTests(unittest.TestCase):
    def assert_denied(self, payload):
        self.assertFalse(accepts_synthetic_http1_fixture(payload))

    def test_positive_get_and_post_are_only_synthetic_shapes(self):
        for payload in (
            request(), posted(), posted(b"", length=b"0"),
            posted(b"x=fixture&y=1"), request(headers=(HOST, b"User-Agent: offline fixture")),
        ):
            with self.subTest(payload=payload[:80]):
                prior = payload[:]
                self.assertTrue(accepts_synthetic_http1_fixture(payload))
                self.assertEqual(payload, prior)

    def test_identical_and_conflicting_duplicate_content_lengths(self):
        for next_length in (b"3", b"4", b"0", b"03"):
            for second_name in (b"Content-Length", b"content-length", b"CONTENT-LENGTH"):
                with self.subTest(value=next_length, name=second_name):
                    self.assert_denied(posted(extra=(second_name + b": " + next_length,)))

    def test_transfer_encoding_and_hop_hints_never_admitted(self):
        for header in (
            b"Transfer-Encoding: chunked",
            b"transfer-encoding: identity",
            b"TrAnSfEr-EnCoDiNg: gzip, chunked",
            b"TE: trailers",
            b"Trailer: Content-Length",
            b"Connection: Transfer-Encoding",
            b"Proxy-Connection: keep-alive",
            b"Upgrade: websocket",
        ):
            with self.subTest(field=header):
                self.assert_denied(posted(extra=(header,)))

    def test_bogus_content_length_tokens_denied(self):
        for token in (
            b"", b"+3", b"-3", b"3.0", b"3e0", b"03", b"0003",
            b"3,3", b"3, 3", b"3 ", b" 3", b"3\t", b"3x",
            b"0x3", b"999999999999999999999999999999999",
            b"\xff", b"\x00", b"true",
        ):
            with self.subTest(token=token):
                self.assert_denied(posted(length=token))

    def test_exact_body_length_or_fail(self):
        self.assert_denied(posted(b"x=1", length=b"2"))
        self.assert_denied(posted(b"x=1", length=b"4"))
        self.assert_denied(posted(b"x=1") + b"x")
        self.assert_denied(posted(b"x=1") + request())
        self.assert_denied(posted(b"x=1")[:-1])
        self.assert_denied(posted(b"x=1", length=b"0"))
        self.assert_denied(posted(b"", length=b"1"))

    def test_get_body_and_framing_fields_denied(self):
        self.assert_denied(request(body=b"X"))
        self.assert_denied(request(headers=(HOST, b"Content-Length: 0")))
        self.assert_denied(request(headers=(HOST, b"Content-Type: text/plain")))

    def test_missing_post_framing_and_malformed_content_type(self):
        self.assert_denied(request(POST, (HOST, FORM), b"x=1"))
        self.assert_denied(request(POST, (HOST, b"Content-Length: 3"), b"x=1"))
        self.assert_denied(request(POST, (HOST, FORM, b"Content-Length: 3", b"Content-Type: x"), b"x=1"))
        self.assert_denied(request(POST, (HOST, b"Content-Type: application/json", b"Content-Length: 3"), b"x=1"))

    def test_crlf_and_header_line_smuggling_shapes_denied(self):
        samples = (
            b"GET /health HTTP/1.1\nHost: localhost\n\n",
            b"GET /health HTTP/1.1\rHost: localhost\r\r",
            b"GET /health HTTP/1.1\r\nHost: localhost\n\r\n",
            b"GET /health HTTP/1.1\r\n Host: localhost\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost : localhost\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost:\tlocalhost\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost:  localhost\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n\tX-More: value\r\n\r\n",
            b"GET /health HTTP/1.1\r\nHost: localhost\r\nX-Extra: one\nanother\r\n\r\n",
        )
        for payload in samples:
            with self.subTest(payload=payload[:90]):
                self.assert_denied(payload)

    def test_host_is_exact_fixture_only(self):
        for host in (b"example.org", b"127.0.0.1", b"localhost:80", b"LOCALHOST",
                     b"localhost.", b"localhost,example.org", b"http://localhost"):
            with self.subTest(host=host):
                self.assert_denied(request(headers=(b"Host: " + host,)))
        self.assert_denied(request(headers=()))
        self.assert_denied(request(headers=(HOST, b"host: localhost")))

    def test_duplicate_casefolded_header_names_denied(self):
        self.assert_denied(request(headers=(HOST, b"X-Test: one", b"x-test: two")))
        self.assert_denied(request(headers=(HOST, b"X-Test: one", b"X-Test: one")))

    def test_external_path_or_non_fixture_method_never_allowed(self):
        for start in (
            b"POST /engagements/1/grants HTTP/1.1",
            b"GET /clients HTTP/1.1",
            b"GET http://localhost/health HTTP/1.1",
            b"CONNECT localhost:443 HTTP/1.1",
            b"TRACE /health HTTP/1.1",
            b"POST /clients HTTP/1.0",
            b"gEt /health HTTP/1.1",
            b"GET /health HTTP/2",
        ):
            with self.subTest(request_line=start):
                self.assert_denied(request(start))

    def test_nonexact_bytes_and_malformed_header_values(self):
        class BytesSubclass(bytes):
            pass

        for wrong in ("GET /health HTTP/1.1", bytearray(request()), memoryview(request()),
                      BytesSubclass(request()), None, True, 1):
            with self.subTest(value=type(wrong).__name__):
                self.assert_denied(wrong)
        for bad in (b"X-Thing: ", b"X-Thing: yes\x7f", b"X-Thing: yes\x01",
                    b"X-Thing: yes\xff", b"X-Thing: trailing ", b"X_Thing: value"):
            with self.subTest(value=bad):
                self.assert_denied(request(headers=(HOST, bad)))

    def test_size_and_field_count_limits(self):
        too_many = tuple(b"X-%d: yes" % i for i in range(MAX_HEADER_FIELDS))
        self.assert_denied(request(headers=(HOST, *too_many)))
        self.assert_denied(posted(b"a" * (MAX_SYNTHETIC_BODY + 1)))
        self.assert_denied(request(headers=(HOST, b"X-Blob: " + b"a" * 17000)))
        self.assert_denied(b"")

    def test_cookie_and_authorization_never_enter_synthetic_fixtures(self):
        for field in (
            b"Cookie: lightup_session=synthetic",
            b"Cookie2: $Version=1",
            b"Authorization: Bearer synthetic",
            b"Proxy-Authorization: Basic synthetic",
            b"Remote-User: operator",
            b"Authentication: operator",
        ):
            with self.subTest(field=field):
                self.assert_denied(request(headers=(HOST, field)))
                self.assert_denied(posted(extra=(field,)))

    def test_forwarded_identity_and_rewrite_hints_refused(self):
        for field in (
            b"Forwarded: for=127.0.0.1",
            b"X-Forwarded-For: 127.0.0.1",
            b"X-Forwarded-Host: localhost",
            b"X-Forwarded-Proto: https",
            b"X-Real-IP: 127.0.0.1",
            b"X-Original-URL: /clients",
            b"X-Rewrite-URL: /clients",
            b"X-Auth-Request-User: operator",
            b"X-Auth-Request-Cookie: synthetic",
            b"X-HTTP-Method-Override: PUT",
            b"X-Method-Override: POST",
        ):
            with self.subTest(field=field):
                self.assert_denied(request(headers=(HOST, field)))
                self.assert_denied(posted(extra=(field,)))

    def test_form_fixture_rejects_raw_controls_binary_and_spaces(self):
        self.assertTrue(accepts_synthetic_http1_fixture(posted(b"x=clean+ascii%20data")))
        for body in (
            b"x=hello world", b"x=line\r\nGET /clients HTTP/1.1",
            b"x=\x00", b"x=\xff", b"x=\tvalue", b"x=\x7f", b"x=\n",
        ):
            with self.subTest(body=body):
                self.assert_denied(posted(body))

    def test_case_and_order_variance_does_not_bypass_checks(self):
        self.assertTrue(accepts_synthetic_http1_fixture(request(
            headers=(b"User-Agent: offline", b"hOsT: localhost"))))
        self.assertTrue(accepts_synthetic_http1_fixture(request(
            POST, (b"content-length: 3", b"hOsT: localhost",
                   b"content-type: application/x-www-form-urlencoded"), b"x=1")))
        self.assert_denied(request(headers=(b"hOsT: localhost", b"HOST: localhost")))


if __name__ == "__main__":
    unittest.main()
