from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.webapp import create_app


class WebAuthorizationInputStrictnessTest(unittest.TestCase):
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
        self.client_context = self.store.context_for_user(self.client_user.user_id)
        self.operator_token, self.operator_csrf = self.store.create_session(
            self.operator_user.user_id
        )
        self.client_token, self.client_csrf = self.store.create_session(
            self.client_user.user_id
        )

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, method, path, form=None, *, token, csrf):
        payload = dict(form or {})
        payload["csrf"] = csrf
        body = urlencode(payload).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
            "HTTP_COOKIE": f"lightup_session={token}",
        }
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = dict(headers)

        response = b"".join(self.app(environ, start_response)).decode()
        return captured["status"], captured["headers"], response

    def _engagement(self):
        return self.store.create_engagement(
            self.operator, self.client.client_id, "Authorized assessment"
        )

    def test_missing_grant_risk_never_defaults_to_standard(self):
        engagement = self._engagement()
        status, _, _ = self.request(
            "POST",
            f"/engagements/{engagement.engagement_id}/grants",
            {
                "approved_by": "CISO",
                "reference": "AUTH-1",
                "assets": "app.acme.example",
                "valid_days": "30",
            },
            token=self.operator_token,
            csrf=self.operator_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            self.store.list_authorization_grants(self.operator, engagement.engagement_id),
            [],
        )

    def test_missing_capabilities_never_means_all(self):
        engagement = self._engagement()
        status, _, _ = self.request(
            "POST",
            f"/engagements/{engagement.engagement_id}/grants",
            {
                "approved_by": "CISO",
                "reference": "AUTH-1",
                "assets": "app.acme.example",
                "max_risk": "3",
                "valid_days": "30",
            },
            token=self.operator_token,
            csrf=self.operator_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            self.store.list_authorization_grants(self.operator, engagement.engagement_id),
            [],
        )

    def test_grant_validity_is_rejected_instead_of_clamped(self):
        engagement = self._engagement()
        for raw_days in ("0", "366", "-1", "1.5", ""):
            with self.subTest(raw_days=raw_days):
                status, _, _ = self.request(
                    "POST",
                    f"/engagements/{engagement.engagement_id}/grants",
                    {
                        "approved_by": "CISO",
                        "reference": "AUTH-1",
                        "assets": "app.acme.example",
                        "max_risk": "3",
                        "valid_days": raw_days,
                    },
                    token=self.operator_token,
                    csrf=self.operator_csrf,
                )
                self.assertEqual(status, "400 Bad Request")
        self.assertEqual(
            self.store.list_authorization_grants(self.operator, engagement.engagement_id),
            [],
        )

    def test_missing_request_risk_never_defaults_to_standard(self):
        status, _, _ = self.request(
            "POST",
            f"/portal/{self.client.client_id}/requests",
            {"assets": "app.acme.example"},
            token=self.client_token,
            csrf=self.client_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(self.store.list_assessment_requests(self.operator), [])

    def test_unknown_assessment_decision_does_not_mutate_request(self):
        request = self.store.submit_assessment_request(
            self.client_context,
            ("app.acme.example",),
            AssessmentMode.AUTHORIZED_ASSESSMENT,
            RiskLevel.LOW_IMPACT,
        )
        status, _, _ = self.request(
            "POST",
            f"/assessments/requests/{request.request_id}/decision",
            {"decision": "approved"},
            token=self.operator_token,
            csrf=self.operator_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        stored = self.store.get_assessment_request(self.operator, request.request_id)
        self.assertEqual(stored.status.value, "submitted")
        self.assertIsNone(stored.decided_by)

    def test_unknown_risk_elevation_decision_does_not_mutate_approval(self):
        engagement = self._engagement()
        approval = self.store.request_risk_elevation(
            self.client_context,
            engagement.engagement_id,
            RiskLevel.ELEVATED,
            "Need the operator to review elevated risk",
        )
        status, _, _ = self.request(
            "POST",
            f"/assessments/elevations/{approval.approval_id}/decision",
            {"decision": "approved"},
            token=self.operator_token,
            csrf=self.operator_csrf,
        )
        self.assertEqual(status, "400 Bad Request")
        stored = self.store.list_risk_approvals(
            self.operator, engagement.engagement_id
        )[0]
        self.assertEqual(stored.status.value, "pending")
        self.assertIsNone(stored.decided_by)


if __name__ == "__main__":
    unittest.main()
