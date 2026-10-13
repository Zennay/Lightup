"""#1023 opt-in envelope non-authority composition with REAL WSGI + SQLite.

Positive JSON shape screening is NOT a signed grant, operator session,
issuer proof, user consent, or permission to test any target. These entirely
offline tests deliberately leave the production WSGI and DomainStore source
unmodified; no external clients/targets, networking, or active tool calls.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from lightup.domain import DomainStore
from lightup.envelope_preflight_optin_1023 import bounded_envelope_shape_optin
from lightup.webapp.app import LightUpWebApp
from lightup.webapp.security import WebSecurity


_TABLES = ("authorization_grants", "assessment_requests", "sessions",
           "engagements", "risk_approvals", "clients", "users")


class ShapeNeverGrantsWSGIAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lightup-1023-shape-")
        self.addCleanup(self.temp.cleanup)
        self.store = DomainStore(Path(self.temp.name) / "offline.sqlite3")
        self.app = LightUpWebApp(self.store, WebSecurity())

    def counts(self):
        with self.store._connect() as connection:
            return tuple(
                connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                for table in _TABLES
            )

    def post(self, route: str, raw: bytes, content_type="application/json",
             **overrides):
        received = []
        env = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": route,
            "HTTP_HOST": "localhost",
            "REMOTE_ADDR": "127.0.0.1",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "wsgi.url_scheme": "http",
            "CONTENT_LENGTH": str(len(raw)),
            "CONTENT_TYPE": content_type,
            "wsgi.input": io.BytesIO(raw),
        }
        env.update(overrides)
        def start_response(status, headers):
            received.append((status, dict(headers)))
        before = self.counts()
        response = b"".join(self.app(env, start_response))
        self.assertEqual(self.counts(), before, "refused input changed durable grant state")
        self.assertEqual(len(received), 1)
        return received[0][0], received[0][1], response

    def test_shape_positive_forged_grant_json_still_has_no_authority(self):
        raw = b'{"issuer":"attacker","tenant":"unowned","approved":true,"risk":5}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, headers, _ = self.post("/engagements/fake/grants", raw)
        self.assertEqual(status, "415 Unsupported Media Type")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_shape_positive_forged_assessment_json_still_has_no_authority(self):
        raw = b'{"requested_risk":5,"scope":["outside.invalid"],"approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post("/portal/other-tenant/requests", raw)
        self.assertEqual(status, "415 Unsupported Media Type")

    def test_valid_surrogate_pair_json_still_has_no_grant(self):
        raw = b'{"\\ud83d\\ude00":true,"approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post("/engagements/fake/grants", raw)
        self.assertEqual(status, "415 Unsupported Media Type")

    def test_unpaired_surrogate_json_rejected_by_parser_and_wsgi(self):
        raw = b'{"tenant":"\\uD800","approved":true}'
        self.assertFalse(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post("/engagements/fake/grants", raw)
        self.assertEqual(status, "415 Unsupported Media Type")

    def test_escaped_aliased_duplicate_identity_rejected_no_state_change(self):
        raw = b'{"tenant":"a","\\u0074enant":"b","approved":true}'
        self.assertFalse(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post("/portal/b/requests", raw)
        self.assertEqual(status, "415 Unsupported Media Type")

    def test_json_as_encoded_form_does_not_bypass_anonymous_grant(self):
        raw = b'{"tenant":"unowned","approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post(
            "/engagements/fake/grants", raw, "application/x-www-form-urlencoded")
        self.assertEqual(status, "400 Bad Request")

    def test_form_like_self_attested_approval_redirected_to_login(self):
        raw = b"csrf=forged&approved=true"
        status, headers, _ = self.post(
            "/engagements/fake/grants", raw, "application/x-www-form-urlencoded")
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")

    def test_json_envelope_wrong_content_length_cannot_mutate_sqlite(self):
        raw = b'{"issuer":"claimed","approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post(
            "/engagements/fake/grants", raw,
            CONTENT_LENGTH="65537",
        )
        self.assertEqual(status, "413 Payload Too Large")

    def test_json_envelope_transfer_framing_cannot_mutate_sqlite(self):
        raw = b'{"issuer":"claimed","approved":true}'
        self.assertTrue(bounded_envelope_shape_optin(raw))
        status, _, _ = self.post(
            "/engagements/fake/grants", raw,
            HTTP_TRANSFER_ENCODING="chunked",
        )
        self.assertEqual(status, "400 Bad Request")


if __name__ == "__main__":
    unittest.main()
