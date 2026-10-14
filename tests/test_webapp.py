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
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
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

    def test_lockout_returns_429(self):
        for _ in range(DomainStore.LOGIN_MAX_FAILURES):
            self.request("POST", "/login",
                         {"email": "op@lightup.test", "password": "wrong-password"})
        status, _, body = self.request(
            "POST", "/login",
            {"email": "op@lightup.test", "password": "operator-password"})
        self.assertEqual(status, "429 Too Many Requests")
        self.assertIn("Too many failed sign-ins", body)

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
        self.assertIsNone(self.store.session_context(self.op_token))
        status, headers, _ = self.request("GET", "/", token=self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], "/login")
        # Revoking one browser must not sign out a different user.
        self.assertIsNotNone(self.store.session_context(self.a_token))

    def test_rejected_logout_keeps_session(self):
        status, _, _ = self.request("POST", "/logout", token=self.op_token,
                                    csrf="forged")
        self.assertEqual(status, "403 Forbidden")
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_successful_login_rotates_existing_session(self):
        status, headers, _ = self.request(
            "POST", "/login",
            {"email": "op@lightup.test", "password": "operator-password"},
            token=self.op_token)
        self.assertEqual(status, "303 See Other")
        self.assertIsNone(self.store.session_context(self.op_token))
        fresh = headers["Set-Cookie"].split("lightup_session=")[1].split(";")[0]
        self.assertIsNotNone(self.store.session_context(fresh))

    def test_bad_login_does_not_revoke_existing_session(self):
        self.request("POST", "/login",
                     {"email": "op@lightup.test", "password": "wrong-password"},
                     token=self.op_token)
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_sensitive_responses_are_not_cached_or_framed(self):
        for method, path, token in [
            ("GET", "/login", None), ("GET", "/", self.op_token),
            ("GET", "/", None), ("GET", "/", self.a_token),
            ("GET", "/missing", self.op_token),
            ("POST", "/logout", self.op_token),
        ]:
            with self.subTest(method=method, path=path, token=bool(token)):
                _, headers, _ = self.request(method, path, token=token)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
                self.assertIn("form-action 'self'", headers["Content-Security-Policy"])
                self.assertIn("base-uri 'none'", headers["Content-Security-Policy"])

    def test_invalid_forms_do_not_mutate_or_authenticate(self):
        from unittest.mock import patch
        cases = [
            (b"name=Bad", "-1", "application/x-www-form-urlencoded", "400"),
            (b"name=%FF", "8", "application/x-www-form-urlencoded", "400"),
            (b"name=Bad", "8", "text/plain", "415"),
            (b"", "65537", "application/x-www-form-urlencoded", "413"),
        ]
        for raw, length, content_type, expected in cases:
            with self.subTest(expected=expected, length=length):
                env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/clients",
                       "CONTENT_LENGTH": length, "CONTENT_TYPE": content_type,
                       "HTTP_COOKIE": f"lightup_session={self.op_token}",
                       "wsgi.input": io.BytesIO(raw)}
                out = {}
                with patch.object(self.store, "session_context") as resolve:
                    b"".join(self.app(env, lambda s, h: out.update(status=s, headers=dict(h))))
                    resolve.assert_not_called()
                self.assertTrue(out["status"].startswith(expected))
                self.assertEqual(out["headers"]["Cache-Control"], "no-store")
        self.assertEqual(len(self.store.list_clients(self.operator)), 2)


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

    def test_operator_creates_engagement_and_grant_via_ui(self):
        status, headers, _ = self.request(
            "POST", f"/clients/{self.client_a.client_id}/engagements",
            {"name": "Q4 assessment"}, token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/clients/{self.client_a.client_id}")
        engagement = self.store.list_engagements(self.operator,
                                                 self.client_a.client_id)[0]
        self.assertEqual(engagement.name, "Q4 assessment")

        status, _, _ = self.request(
            "POST", f"/engagements/{engagement.engagement_id}/grants",
            {"approved_by": "CISO Acme", "reference": "AUTH-2026-007",
             "assets": "app.acme.example, api.acme.example",
             "excluded_assets": "legacy.acme.example",
             "capabilities": "web-baseline", "max_risk": "3", "valid_days": "30"},
            token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "303 See Other")
        grant = self.store.get_current_grant(self.operator, engagement.engagement_id)
        self.assertIsNotNone(grant)
        self.assertEqual(grant.reference, "AUTH-2026-007")
        self.assertEqual(grant.scope.assets, ("app.acme.example", "api.acme.example"))
        self.assertFalse(grant.scope.allows_asset("legacy.acme.example"))
        _, _, body = self.request("GET", f"/clients/{self.client_a.client_id}",
                                  token=self.op_token)
        self.assertIn("Authorization current", body)
        self.assertIn("Revoke authorization", body)

        status, headers, _ = self.request(
            "POST",
            f"/engagements/{engagement.engagement_id}/authorization/revoke",
            {"reason": "Customer withdrew authorization"},
            token=self.op_token,
            csrf=self.op_csrf,
        )
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/clients/{self.client_a.client_id}")
        self.assertIsNone(
            self.store.get_current_grant(self.operator, engagement.engagement_id)
        )
        grants = self.store.list_authorization_grants(
            self.operator, engagement.engagement_id
        )
        self.assertTrue(all(grant.is_revoked for grant in grants))
        self.assertTrue(
            all(
                grant.revocation_reason == "Customer withdrew authorization"
                for grant in grants
            )
        )
        _, _, body = self.request(
            "GET", f"/clients/{self.client_a.client_id}", token=self.op_token
        )
        self.assertIn("No current authorization", body)
        self.assertIn("Revoked authorization history", body)
        self.assertIn("Customer withdrew authorization", body)
        self.assertIn("AUTH-2026-007", body)

        # Capability scope is mandatory; omission fails closed.
        status, _, _ = self.request(
            "POST", f"/engagements/{engagement.engagement_id}/grants",
            {"approved_by": "CISO Acme", "reference": "AUTH-NO-CAPS",
             "assets": "app.acme.example", "max_risk": "3", "valid_days": "30"},
            token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "400 Bad Request")

        # Destructive risk cannot be granted through the UI.
        status, _, _ = self.request(
            "POST", f"/engagements/{engagement.engagement_id}/grants",
            {"approved_by": "X", "reference": "R", "assets": "a",
             "max_risk": "5", "valid_days": "30"},
            token=self.op_token, csrf=self.op_csrf)
        self.assertEqual(status, "400 Bad Request")

    def test_client_session_cannot_create_engagement_or_grant(self):
        status, _, _ = self.request(
            "POST", f"/clients/{self.client_a.client_id}/engagements",
            {"name": "Rogue"}, token=self.a_token, csrf=self.a_csrf)
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.store.list_engagements(self.operator), [])

    def test_client_session_cannot_revoke_authorization(self):
        engagement = self.store.create_engagement(
            self.operator, self.client_a.client_id, "Authorized"
        )
        status, _, _ = self.request(
            "POST",
            f"/engagements/{engagement.engagement_id}/authorization/revoke",
            {"reason": "rogue revoke"},
            token=self.a_token,
            csrf=self.a_csrf,
        )
        self.assertEqual(status, "403 Forbidden")

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
