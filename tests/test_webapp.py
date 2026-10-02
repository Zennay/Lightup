from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.models import Severity
from lightup.webapp import create_app


class WebAppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = DomainStore(Path(self.tmp.name) / "domain.db")
        self.app = create_app(self.store)
        self.operator = AccessContext("op-1", Role.OPERATOR)
        self.client_a = self.store.create_client(self.operator, "Acme BV")
        self.client_b = self.store.create_client(self.operator, "Globex NV")

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, method: str, path: str, form: dict | None = None):
        body = urlencode(form or {}).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        captured: dict = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        chunks = self.app(environ, start_response)
        return captured["status"], captured["headers"], b"".join(chunks).decode()

    def test_admin_pages_render(self):
        for path, marker in (
            ("/", "Active testing"),
            ("/discovery", "Passive only"),
            ("/clients", "Acme BV"),
            ("/assessments", "authorization grant"),
        ):
            status, _, body = self.request("GET", path)
            self.assertEqual(status, "200 OK", path)
            self.assertIn(marker, body, path)
        status, _, _ = self.request("GET", "/nope")
        self.assertEqual(status, "404 Not Found")

    def test_overview_shows_locked_activation(self):
        _, _, body = self.request("GET", "/")
        self.assertIn("Locked", body)
        self.assertIn("no real-target execution path", body)

    def test_prospect_card_is_minimal_and_locked(self):
        self.store.add_prospect(self.operator, "Initech", "Exposed admin login", 0.7)
        _, _, body = self.request("GET", "/discovery")
        self.assertIn("Initech", body)
        self.assertIn("Active testing: Locked", body)
        self.assertIn("View signals", body)
        self.assertIn("Contact", body)
        # Raw signal/tool output never appears at the first level.
        self.assertNotIn("raw", body.lower())

    def test_portal_tenant_isolation(self):
        engagement = self.store.create_engagement(self.operator, self.client_a.client_id, "Q4")
        self.store.record_finding(
            self.operator, engagement.engagement_id, "Secret-A-finding", Severity.HIGH,
            "app.acme.example", "Account takeover", "Rotate credentials and add MFA",
        )
        _, _, body_a = self.request("GET", f"/portal/{self.client_a.client_id}")
        self.assertIn("Secret-A-finding", body_a)
        _, _, body_b = self.request("GET", f"/portal/{self.client_b.client_id}")
        self.assertNotIn("Secret-A-finding", body_b)

    def test_portal_submits_assessment_request(self):
        status, headers, _ = self.request(
            "POST", f"/portal/{self.client_a.client_id}/requests",
            {"assets": "app.acme.example, api.acme.example", "risk": "3", "notes": "please"},
        )
        self.assertEqual(status, "303 See Other")
        self.assertEqual(headers["Location"], f"/portal/{self.client_a.client_id}")
        ctx = AccessContext("u", Role.CLIENT_ADMIN, self.client_a.client_id)
        requests = self.store.list_assessment_requests(ctx)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].requested_assets,
                         ("app.acme.example", "api.acme.example"))
        self.assertIs(requests[0].requested_mode, AssessmentMode.AUTHORIZED_ASSESSMENT)
        self.assertIs(requests[0].requested_risk, RiskLevel.STANDARD)

    def test_portal_cannot_request_destructive_risk(self):
        status, _, _ = self.request(
            "POST", f"/portal/{self.client_a.client_id}/requests",
            {"assets": "app.acme.example", "risk": "5"},
        )
        self.assertEqual(status, "400 Bad Request")
        ctx = AccessContext("u", Role.CLIENT_ADMIN, self.client_a.client_id)
        self.assertEqual(self.store.list_assessment_requests(ctx), [])

    def test_operator_can_decide_request_via_ui(self):
        self.request("POST", f"/portal/{self.client_a.client_id}/requests",
                     {"assets": "app.acme.example", "risk": "2"})
        request_id = self.store.list_assessment_requests(
            self.operator)[0].request_id
        status, _, _ = self.request(
            "POST", f"/assessments/requests/{request_id}/decision",
            {"decision": "approve"})
        self.assertEqual(status, "303 See Other")
        self.assertEqual(
            self.store.list_assessment_requests(self.operator)[0].status.value, "approved")

    def test_unknown_portal_client_is_an_error_not_a_leak(self):
        status, _, body = self.request("GET", "/portal/does-not-exist")
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn("Acme", body)

    def test_output_is_escaped(self):
        self.store.add_prospect(self.operator, "<script>alert(1)</script>", "x", 0.5)
        _, _, body = self.request("GET", "/discovery")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_no_active_execution_routes_exist(self):
        # The web shell must not expose any route that could trigger target
        # interaction: every route is a domain-store read or write.
        for method, pattern, _handler in self.app.routes:
            self.assertNotRegex(pattern.pattern, r"(scan|exploit|probe|execute|attack)")


if __name__ == "__main__":
    unittest.main()
