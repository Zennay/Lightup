from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.models import Severity
from lightup.webapp import create_app


class WebAppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.app = create_app(self.store)
        self.op_user = self.store.bootstrap_operator(
            "op@lightup.test", "Operator", "operator-password")
        self.operator = self.store.context_for_user(self.op_user.user_id)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")
        self.user_a = self.store.create_user(self.operator, "a@acme.test", "A",
                                             Role.CLIENT_ADMIN, self.client_a.client_id)
        self.store.set_password(self.operator, self.user_a.user_id, "client-a-password")
        self.op_token, self.op_csrf = self.store.create_session(self.op_user.user_id)
        self.a_token, self.a_csrf = self.store.create_session(self.user_a.user_id)

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, method: str, path: str, form: dict | None = None,
                token: str | None = None, csrf: str | None = None):
        form = dict(form or {})
        if csrf is not None:
            form.setdefault("csrf", csrf)
        body = urlencode(form).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        if token:
            environ["HTTP_COOKIE"] = f"lightup_session={token}"
        captured: dict = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        chunks = self.app(environ, start_response)
        headers = dict(captured["headers"])
        return captured["status"], headers, b"".join(chunks).decode()

    # -- authentication ------------------------------------------------------

    def test_anonymous_is_redirected_to_login(self):
        for path in ("/", "/discovery", "/clients", "/assessments",
                     f"/portal/{self.client_a.client_id}"):
            status, headers, _ = self.request("GET", path)
            self.assertEqual(status, "303 See Other", path)
            self.assertEqual(headers["Location"], "/login", path)

    def test_login_flow(self):
        status, _, body = self.request("GET", "/login")
        self.assertEqual(status, "200 OK")
        self.assertIn("Sign in", body)

        status, headers, _ = self.request(
            "POST", "/login", {"email": "op@lightup.test", "password": "operator-password"})
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/")
        self.assertIn("lightup_session=", headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        token = headers["Set-Cookie"].split("lightup_session=")[1].split(";")[0]
        status, _, body = self.request("GET", "/", token=token)
        self.assertEqual(status, "200 OK")
        self.assertIn("Active testing", body)

    def test_bad_login_rejected(self):
        status, _, body = self.request(
            "POST", "/login", {"email": "op@lightup.test", "password": "wrong-password"})
        self.assertEqual(status, "401 Unauthorized")
        self.assertIn("Invalid email or password", body)

    def test_client_login_lands_on_portal(self):
        status, headers, _ = self.request(
            "POST", "/login", {"email": "a@acme.test", "password": "client-a-password"})
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/portal/{self.client_a.client_id}")

    def test_client_session_cannot_reach_admin_or_other_portal(self):
        for path in ("/", "/discovery", "/clients", "/assessments"):
            status, _, _ = self.request("GET", path, token=self.a_token)
            self.assertEqual(status, "403 Forbidden", path)
        status, _, _ = self.request("GET", f"/portal/{self.client_b.client_id}",
                                    token=self.a_token)
        self.assertEqual(status, "403 Forbidden")

    def test_posts_require_csrf(self):
        status, _, _ = self.request("POST", "/clients", {"name": "Evil"},
                                    token=self.op_token)
        self.assertEqual(status, "403 Forbidden")
        status, _, _ = self.request("POST", "/clients", {"name": "Evil"},
                                    token=self.op_token, csrf="forged")
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(len(self.store.list_clients(self.operator)), 2)
        status, _, _ = self.request("POST", "/clients", {"name": "Legit BV"},
                                    token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(len(self.store.list_clients(self.operator)), 3)

    def test_logout_clears_session(self):
        status, headers, _ = self.request("POST", "/logout", token=self.op_token,
                                          csrf=self.op_csrf)
        self.assertEqual(status, "303 See Other")
        self.assertIn("Max-Age=0", headers["Set-Cookie"])

    # -- pages ----------------------------------------------------------------

    def test_admin_pages_render(self):
        for path, marker in (
            ("/", "Active testing"),
            ("/discovery", "Passive only"),
            ("/clients", "Acme BV"),
            ("/assessments", "authorization grant"),
        ):
            status, _, body = self.request("GET", path, token=self.op_token)
            self.assertEqual(status, "200 OK", path)
            self.assertIn(marker, body, path)
        status, _, _ = self.request("GET", "/nope", token=self.op_token)
        self.assertEqual(status, "404 Not Found")

    def test_prospect_card_is_minimal_and_locked(self):
        self.store.add_prospect(self.operator, "Initech", "Exposed admin login", 0.7)
        _, _, body = self.request("GET", "/discovery", token=self.op_token)
        self.assertIn("Initech", body)
        self.assertIn("Active testing: Locked", body)
        self.assertIn("View signals", body)
        self.assertIn("Contact", body)

    def test_portal_tenant_isolation(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        self.store.record_finding(
            self.operator, engagement.engagement_id, "Secret-A-finding", Severity.HIGH,
            "app.acme.example", "Account takeover", "Rotate credentials and add MFA",
        )
        _, _, body_a = self.request("GET", f"/portal/{self.client_a.client_id}",
                                    token=self.a_token)
        self.assertIn("Secret-A-finding", body_a)
        # The operator can view any portal; client B's session cannot see A's.
        _, _, body_op = self.request("GET", f"/portal/{self.client_b.client_id}",
                                     token=self.op_token)
        self.assertNotIn("Secret-A-finding", body_op)

    def test_portal_submits_assessment_request(self):
        status, headers, _ = self.request(
            "POST", f"/portal/{self.client_a.client_id}/requests",
            {"assets": "app.acme.example, api.acme.example", "risk": "3", "notes": "please"},
            token=self.a_token, csrf=self.a_csrf,
        )
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/portal/{self.client_a.client_id}")
        requests = self.store.list_assessment_requests(self.operator)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].requested_assets,
                         ("app.acme.example", "api.acme.example"))
        self.assertIs(requests[0].requested_mode, AssessmentMode.AUTHORIZED_ASSESSMENT)
        self.assertIs(requests[0].requested_risk, RiskLevel.STANDARD)
        self.assertEqual(requests[0].requested_by, self.user_a.user_id)

    def test_portal_cannot_request_destructive_risk(self):
        status, _, _ = self.request(
            "POST", f"/portal/{self.client_a.client_id}/requests",
            {"assets": "app.acme.example", "risk": "5"},
            token=self.a_token, csrf=self.a_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(self.store.list_assessment_requests(self.operator), [])

    def test_operator_can_decide_request_via_ui(self):
        self.request("POST", f"/portal/{self.client_a.client_id}/requests",
                     {"assets": "app.acme.example", "risk": "2"},
                     token=self.a_token, csrf=self.a_csrf)
        request_id = self.store.list_assessment_requests(self.operator)[0].request_id
        status, _, _ = self.request(
            "POST", f"/assessments/requests/{request_id}/decision",
            {"decision": "approve"}, token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "303 See Other")
        decided = self.store.list_assessment_requests(self.operator)[0]
        self.assertEqual(decided.status.value, "approved")
        self.assertEqual(decided.decided_by, self.op_user.user_id)

    def test_output_is_escaped(self):
        self.store.add_prospect(self.operator, "<script>alert(1)</script>", "x", 0.5)
        _, _, body = self.request("GET", "/discovery", token=self.op_token)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_no_active_execution_routes_exist(self):
        for _method, pattern, _handler, _access in self.app.routes:
            self.assertNotRegex(pattern.pattern, r"(scan|exploit|probe|execute|attack)")


if __name__ == "__main__":
    unittest.main()
