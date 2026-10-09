"""Fail-closed WSGI form envelope and stream regressions.

No HTTP server, target I/O, or authorization grants. Exercises the real
production parser and web shell with synthetic WSGI environments.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from lightup.domain import DomainStore
from lightup.webapp import create_app
from lightup.webapp.forms import FormError, read_form


class BrokenStream:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def read(self, n):
        if self.error is not None:
            raise self.error
        return self.result


class MustNotRead:
    def read(self, n):
        raise AssertionError("invalid WSGI envelope was read")


def valid_env(body=b"name=A"):
    return {
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "wsgi.input": io.BytesIO(body),
    }


class FormEnvelopeStrictnessTests(unittest.TestCase):
    def test_content_type_must_be_actual_string_before_read(self):
        for invalid in (
            None, False, 0, 1, [], {},
            b"application/x-www-form-urlencoded", object(),
        ):
            with self.subTest(content_type=repr(invalid)):
                env = valid_env()
                env["CONTENT_TYPE"] = invalid
                env["wsgi.input"] = MustNotRead()
                with self.assertRaises(FormError) as caught:
                    read_form(env)
                self.assertEqual(caught.exception.status, "415 Unsupported Media Type")

    def test_bad_stream_or_bad_read_result_rejected_not_crashed(self):
        cases = [
            ("missing", None, True),
            ("none", None, False),
            ("no-read", object(), False),
            ("text", BrokenStream("name=A"), False),
            ("bytearray", BrokenStream(bytearray(b"name=A")), False),
            ("memoryview", BrokenStream(memoryview(b"name=A")), False),
            ("os-error", BrokenStream(error=OSError("synthetic I/O fault")), False),
            ("value-error", BrokenStream(error=ValueError("closed synthetic stream")), False),
            ("eof-error", BrokenStream(error=EOFError("synthetic truncated stream")), False),
        ]
        for label, stream, delete in cases:
            with self.subTest(case=label):
                env = valid_env()
                if delete:
                    env.pop("wsgi.input")
                else:
                    env["wsgi.input"] = stream
                with self.assertRaises(FormError) as caught:
                    read_form(env)
                self.assertEqual(caught.exception.status, "400 Bad Request")

    def test_transfer_encoding_metadata_is_exact_string_or_absent(self):
        # A non-empty transfer framing hint is never accepted, including
        # falsey polymorphic values that would bypass plain truthiness.
        for suspicious in (False, 0, [], {}, b"", "chunked", "identity"):
            with self.subTest(value=repr(suspicious)):
                env = valid_env()
                env["HTTP_TRANSFER_ENCODING"] = suspicious
                env["wsgi.input"] = MustNotRead()
                with self.assertRaises(FormError) as caught:
                    read_form(env)
                self.assertEqual(caught.exception.status, "400 Bad Request")

        self.assertEqual(
            read_form({**valid_env(), "HTTP_TRANSFER_ENCODING": ""}),
            {"name": "A"},
        )

    def test_valid_stream_and_optional_content_type_parameters_unchanged(self):
        env = valid_env(b"csrf=safe&name=Allowed")
        env["CONTENT_TYPE"] = "application/x-www-form-urlencoded; charset=utf-8"
        self.assertEqual(
            read_form(env),
            {"csrf": "safe", "name": "Allowed"},
        )


class WebAppMalformedEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tempdir.name) / "state.db")
        self.user = self.store.bootstrap_operator(
            "envelope@lightup.test", "Operator", "operator-password"
        )
        self.ctx = self.store.context_for_user(self.user.user_id)
        self.token, self.csrf = self.store.create_session(self.user.user_id)
        self.app = create_app(self.store)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_no_session_lookup_or_mutation_after_invalid_wsgi_envelope(self):
        body = urlencode({"csrf": self.csrf, "name": "Must not exist"}).encode()
        bad_cases = [
            ("typed-content", {"CONTENT_TYPE": b"application/x-www-form-urlencoded"}, MustNotRead(), "415 "),
            ("typed-transfer", {"HTTP_TRANSFER_ENCODING": 0}, MustNotRead(), "400 "),
            ("missing-stream", {}, None, "400 "),
            ("broken-stream", {}, BrokenStream(error=OSError("synthetic read failure")), "400 "),
            ("text-stream", {}, BrokenStream(body.decode()), "400 "),
        ]
        for name, override, stream, expected in bad_cases:
            with self.subTest(case=name):
                env = {
                    "REQUEST_METHOD": "POST",
                    "PATH_INFO": "/clients",
                    "HTTP_HOST": "localhost",
                    "HTTP_ORIGIN": "http://localhost",
                    "HTTP_COOKIE": f"lightup_session={self.token}",
                    "CONTENT_LENGTH": str(len(body)),
                    "CONTENT_TYPE": "application/x-www-form-urlencoded",
                    "wsgi.input": io.BytesIO(body),
                    **override,
                }
                if name == "missing-stream":
                    del env["wsgi.input"]
                else:
                    env["wsgi.input"] = stream
                seen = {}

                def start_response(status, headers):
                    seen["status"] = status
                    seen["headers"] = dict(headers)

                before = len(self.store.list_clients(self.ctx))
                with patch.object(self.store, "session_context") as lookup:
                    list(self.app(env, start_response))
                    lookup.assert_not_called()
                self.assertTrue(seen["status"].startswith(expected), seen["status"])
                self.assertEqual(seen["headers"]["Cache-Control"], "no-store")
                self.assertIsNotNone(self.store.session_context(self.token))
                self.assertEqual(len(self.store.list_clients(self.ctx)), before)


if __name__ == "__main__":
    unittest.main()
