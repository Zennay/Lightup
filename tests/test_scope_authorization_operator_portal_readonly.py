from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app


class OperatorPortalWriteBoundaryTests(unittest.TestCase):
    """Acceptance contract for read-only operator access to client portals."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.app = create_app(self.store)

        self.operator_user = self.store.bootstrap_operator(
            "operator@lightup.test", "Operator", "operator-password"
        )
        self.operator = self.store.context_for_user(self.operator_user.user_id)
        self.client = self.store.create_client(self.operator, "Acme BV")
        self.client_user = self.store.create_user(
            self.operator,
            "admin@acme.test",
            "Acme Admin",
            Role.CLIENT_ADMIN,
            self.client.client_id,
        )
        self.store.set_password(
            self.operator, self.client_user.user_id, "client-admin-password"
        )

        self.operator_token, self.operator_csrf = self.store.create_session(
            self.operator_user.user_id
        )
        self.client_token, self.client_csrf = self.store.create_session(
            self.client_user.user_id
        )

    def tearDown(self):
        self.tmp.cleanup()

    def request(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None = None,
        *,
        token: str | None = None,
        csrf: str | None = None,
    ):
        payload = dict(form or {})
        if csrf is not None:
            payload.setdefault("csrf", csrf)
        body = urlencode(payload).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
        }
        if token is not None:
            environ["HTTP_COOKIE"] = f"lightup_session={token}"

        captured: dict[str, object] = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        response = b"".join(self.app(environ, start_response)).decode("utf-8")
        return str(captured["status"]), dict(captured["headers"]), response

    def test_operator_can_view_portal_without_client_write_affordance(self):
        status, _, body = self.request(
            "GET",
            f"/portal/{self.client.client_id}",
            token=self.operator_token,
        )

        self.assertEqual(status, "200 OK")
        self.assertIn("Acme BV", body)
        self.assertNotIn(
            f'action="/portal/{self.client.client_id}/requests"',
            body,
        )
        self.assertEqual(self.store.list_assessment_requests(self.operator), [])

    def test_operator_cannot_submit_client_portal_assessment_request(self):
        status, _, _ = self.request(
            "POST",
            f"/portal/{self.client.client_id}/requests",
            {
                "assets": "app.acme.example",
                "risk": "2",
                "notes": "operator must not impersonate a client requester",
            },
            token=self.operator_token,
            csrf=self.operator_csrf,
        )

        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.store.list_assessment_requests(self.operator), [])

    def test_matching_client_session_keeps_write_affordance_and_request_provenance(self):
        get_status, _, get_body = self.request(
            "GET",
            f"/portal/{self.client.client_id}",
            token=self.client_token,
        )
        self.assertEqual(get_status, "200 OK")
        self.assertIn(
            f'action="/portal/{self.client.client_id}/requests"',
            get_body,
        )

        status, headers, _ = self.request(
            "POST",
            f"/portal/{self.client.client_id}/requests",
            {
                "assets": "app.acme.example",
                "risk": "2",
                "notes": "client-originated request",
            },
            token=self.client_token,
            csrf=self.client_csrf,
        )

        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/portal/{self.client.client_id}")
        requests = self.store.list_assessment_requests(self.operator)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].client_id, self.client.client_id)
        self.assertEqual(requests[0].requested_by, self.client_user.user_id)


if __name__ == "__main__":
    unittest.main()
