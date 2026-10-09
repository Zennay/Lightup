"""Real-WSGI, offline identity-header non-authority regressions.

Synthetic HTTP/WSGI environments only. No listeners, external targets,
assessment execution, grants, or deployment. This file is owned independently
of production webapp/security and other workers' tests.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.webapp import create_app
from lightup.webapp.security import WebSecurity


# Upstream-provided identity conventions and user-controlled HTTP counterparts
# must never be accepted as substitutes for LightUp's server-side session.
SPOOFED_IDENTITIES = (
    ("REMOTE_USER", "op@lightup.test"),
    ("AUTH_TYPE", "Basic"),
    ("HTTP_AUTHORIZATION", "Bearer pretend-operator"),
    ("HTTP_X_REMOTE_USER", "op@lightup.test"),
    ("HTTP_X_AUTH_REQUEST_USER", "op@lightup.test"),
    ("HTTP_X_FORWARDED_USER", "op@lightup.test"),
    ("HTTP_X_FORWARDED_EMAIL", "op@lightup.test"),
    ("HTTP_X_USER", "op@lightup.test"),
    ("HTTP_X_API_KEY", "pretend-operator-key"),
)


class WsgiIdentityMetadataNonauthorityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = DomainStore(Path(self.tmp.name) / "web.db")
        self.operator_user = self.store.bootstrap_operator(
            "op@lightup.test", "Operator", "operator-password"
        )
        self.operator_ctx = self.store.context_for_user(self.operator_user.user_id)
        self.client_a = self.store.create_client(self.operator_ctx, "Client A")
        self.client_b = self.store.create_client(self.operator_ctx, "Client B")
        self.client_user = self.store.create_user(
            self.operator_ctx, "client@lightup.test", "Client Admin",
            Role.CLIENT_ADMIN, self.client_a.client_id,
        )
        self.op_token, self.op_csrf = self.store.create_session(self.operator_user.user_id)
        self.client_token, self.client_csrf = self.store.create_session(self.client_user.user_id)

    def app_for(self, mode):
        if mode == "production":
            return create_app(self.store, WebSecurity("https://lightup.example.test"))
        return create_app(self.store, WebSecurity())

    def request(self, mode, method, path, *, token=None, form=None, extra=None):
        body = urlencode(form or {}).encode("utf-8")
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_HOST": "lightup.example.test" if mode == "production" else "localhost",
            "HTTP_ORIGIN": "https://lightup.example.test" if mode == "production"
                           else "http://localhost",
        }
        if mode == "production":
            env["HTTP_X_FORWARDED_PROTO"] = "https"
        if token is not None:
            env["HTTP_COOKIE"] = f"lightup_session={token}"
        env.update(extra or {})
        outcome = {}

        def respond(status, headers):
            outcome["status"] = status
            outcome["headers"] = dict(headers)

        payload = b"".join(self.app_for(mode)(env, respond)).decode("utf-8")
        return outcome["status"], outcome["headers"], payload

    def assert_no_new_clients(self):
        self.assertEqual(
            {c.client_id for c in self.store.list_clients(self.operator_ctx)},
            {self.client_a.client_id, self.client_b.client_id},
        )

    def test_anonymous_identity_metadata_never_opens_admin_or_other_portal(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                for path in ("/", "/clients", "/assessments",
                             f"/portal/{self.client_b.client_id}"):
                    with self.subTest(mode=mode, key=key, path=path):
                        status, headers, body = self.request(
                            mode, "GET", path, extra={key: value}
                        )
                        self.assertEqual(status, "303 See Other")
                        self.assertEqual(headers["Location"], "/login")
                        self.assertEqual(headers["Cache-Control"], "no-store")
                        self.assertNotIn("Client B", body)
        self.assert_no_new_clients()

    def test_anonymous_identity_metadata_cannot_create_even_with_operator_csrf(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "POST", "/clients",
                        form={"csrf": self.op_csrf, "name": "Forged"},
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_client_cookie_cannot_be_promoted_to_operator_by_identity_metadata(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, _, _ = self.request(
                        mode, "GET", "/clients", token=self.client_token,
                        extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    status, _, body = self.request(
                        mode, "GET", f"/portal/{self.client_b.client_id}",
                        token=self.client_token, extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assertNotIn("Client B", body)
        self.assert_no_new_clients()

    def test_client_csrf_with_forged_operator_identity_cannot_write(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, _, _ = self.request(
                        mode, "POST", "/clients", token=self.client_token,
                        form={"csrf": self.client_csrf, "name": "Forged"},
                        extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_spoofed_csrf_header_cannot_replace_missing_or_invalid_form_csrf(self):
        for mode in ("development", "production"):
            for form in ({"name": "Forged"}, {"name": "Forged", "csrf": "invalid"}):
                with self.subTest(mode=mode, form=form):
                    status, _, _ = self.request(
                        mode, "POST", "/clients", token=self.op_token,
                        form=form, extra={"HTTP_X_CSRF_TOKEN": self.op_csrf,
                                          "HTTP_X_AUTH_REQUEST_USER": "op@lightup.test"},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assert_no_new_clients()
        self.assertIsNotNone(self.store.session_context(self.op_token))

    def test_spoofed_identity_logout_without_session_does_not_revoke_other_sessions(self):
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "POST", "/logout", form={"csrf": self.op_csrf},
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertIsNotNone(self.store.session_context(self.op_token))
                    self.assertIsNotNone(self.store.session_context(self.client_token))

    def test_revoked_cookie_cannot_be_resurrected_by_wsgi_identity(self):
        self.store.revoke_session(self.op_token)
        self.assertIsNone(self.store.session_context(self.op_token))
        for mode in ("development", "production"):
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key):
                    status, headers, _ = self.request(
                        mode, "GET", "/clients", token=self.op_token,
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
        self.assert_no_new_clients()


    def test_alternate_cookie_headers_cannot_supply_a_session(self):
        # A proxy's alias/copy of Cookie is not LightUp's canonical Cookie.
        # If an upstream proxy rewrites it to HTTP_COOKIE, that different
        # ingress behavior needs an installed-proxy acceptance test.
        copied = f"lightup_session={self.op_token}"
        for mode in ("development", "production"):
            for header in ("HTTP_X_FORWARDED_COOKIE", "HTTP_X_ORIGINAL_COOKIE",
                           "HTTP_X_AUTH_REQUEST_COOKIE", "HTTP_COOKIE2"):
                with self.subTest(mode=mode, header=header):
                    status, headers, _ = self.request(
                        mode, "GET", "/clients", extra={header: copied},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    status, headers, _ = self.request(
                        mode, "POST", "/clients",
                        form={"name": "Forged", "csrf": self.op_csrf},
                        extra={header: copied},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assert_no_new_clients()

    def test_identity_metadata_cannot_issue_operator_only_scope_grants(self):
        # Grant records are temporary SQLite fixtures, NEVER actual
        # authorization for target contact or production execution.
        for mode in ("development", "production"):
            engagement = self.store.create_engagement(
                self.operator_ctx, self.client_a.client_id,
                f"Offline authority fixture {mode}",
            )
            path = f"/engagements/{engagement.engagement_id}/grants"
            form = {
                "approved_by": "Synthetic approver",
                "reference": f"OFFLINE-{mode}",
                "assets": "fixture.invalid",
                "capabilities": "web-baseline",
                "max_risk": "1",
                "valid_days": "7",
            }
            for key, value in SPOOFED_IDENTITIES:
                with self.subTest(mode=mode, key=key, session="anonymous"):
                    status, headers, _ = self.request(
                        mode, "POST", path,
                        form={**form, "csrf": self.op_csrf},
                        extra={key: value},
                    )
                    self.assertEqual(status, "303 See Other")
                    self.assertEqual(headers["Location"], "/login")
                    self.assertIsNone(self.store.get_current_grant(
                        self.operator_ctx, engagement.engagement_id))
                with self.subTest(mode=mode, key=key, session="client"):
                    status, _, _ = self.request(
                        mode, "POST", path, token=self.client_token,
                        form={**form, "csrf": self.client_csrf},
                        extra={key: value},
                    )
                    self.assertEqual(status, "403 Forbidden")
                    self.assertIsNone(self.store.get_current_grant(
                        self.operator_ctx, engagement.engagement_id))
            # Synthetic positive control: operator's actual session+form CSRF,
            # not a forged upstream identity, controls grant-record admission.
            status, headers, _ = self.request(
                mode, "POST", path, token=self.op_token,
                form={**form, "csrf": self.op_csrf},
                extra={"REMOTE_USER": "client@lightup.test"},
            )
            self.assertEqual(status, "303 See Other")
            self.assertEqual(headers["Location"],
                             f"/clients/{self.client_a.client_id}")
            self.assertIsNotNone(self.store.get_current_grant(
                self.operator_ctx, engagement.engagement_id))

    def test_forged_identity_cannot_approve_assessment_requests(self):
        client_ctx = self.store.context_for_user(self.client_user.user_id)
        for mode in ("development", "production"):
            pending = self.store.submit_assessment_request(
                client_ctx, requested_assets=("fixture.invalid",),
                requested_mode=AssessmentMode.AUTHORIZED_ASSESSMENT,
                requested_risk=RiskLevel.LOW_IMPACT,
                notes="offline no-target decision fixture",
            )
            path = f"/assessments/requests/{pending.request_id}/decision"
            for key, value in SPOOFED_IDENTITIES:
                for token, csrf, wanted_status in (
                    (None, self.op_csrf, "303 See Other"),
                    (self.client_token, self.client_csrf, "403 Forbidden"),
                ):
                    with self.subTest(mode=mode, key=key,
                                      identity="anonymous" if token is None else "client"):
                        status, headers, _ = self.request(
                            mode, "POST", path, token=token,
                            form={"csrf": csrf, "decision": "approve"},
                            extra={key: value},
                        )
                        self.assertEqual(status, wanted_status)
                        if token is None:
                            self.assertEqual(headers["Location"], "/login")
                        observed = self.store.get_assessment_request(
                            self.operator_ctx, pending.request_id
                        )
                        self.assertEqual(observed.status.value, "submitted")
                        self.assertIsNone(observed.decided_by)
                        self.assertIsNone(observed.decided_at)
            # Only the genuine operator session and body CSRF may decide.
            status, headers, _ = self.request(
                mode, "POST", path, token=self.op_token,
                form={"csrf": self.op_csrf, "decision": "approve"},
                extra={"REMOTE_USER": "client@lightup.test"},
            )
            self.assertEqual(status, "303 See Other")
            self.assertEqual(headers["Location"], "/assessments")
            decided = self.store.get_assessment_request(
                self.operator_ctx, pending.request_id
            )
            self.assertEqual(decided.status.value, "approved")
            self.assertEqual(decided.decided_by, self.operator_user.user_id)
        # Approving a request is not an execution or authorization grant.
        self.assertEqual(self.store.list_authorization_grants(self.operator_ctx,
                         self.store.create_engagement(
                             self.operator_ctx, self.client_a.client_id,
                             "no active target authorization fixture",
                         ).engagement_id), [])

    def test_forged_identity_cannot_approve_risk_elevation(self):
        client_ctx = self.store.context_for_user(self.client_user.user_id)
        for mode in ("development", "production"):
            engagement = self.store.create_engagement(
                self.operator_ctx, self.client_a.client_id,
                f"Offline risk decision fixture {mode}",
            )
            pending = self.store.request_risk_elevation(
                client_ctx, engagement.engagement_id, RiskLevel.STANDARD,
                "synthetic review-only scenario",
            )
            path = f"/assessments/elevations/{pending.approval_id}/decision"
            for key, value in SPOOFED_IDENTITIES:
                for token, csrf, expected_status in (
                    (None, self.op_csrf, "303 See Other"),
                    (self.client_token, self.client_csrf, "403 Forbidden"),
                ):
                    with self.subTest(mode=mode, key=key,
                                      identity="anonymous" if token is None else "client"):
                        status, headers, _ = self.request(
                            mode, "POST", path, token=token,
                            form={"csrf": csrf, "decision": "approve"},
                            extra={key: value},
                        )
                        self.assertEqual(status, expected_status)
                        if token is None:
                            self.assertEqual(headers["Location"], "/login")
                        observed = self.store.list_risk_approvals(
                            self.operator_ctx, engagement.engagement_id
                        )[0]
                        self.assertEqual(observed.status.value, "pending")
                        self.assertIsNone(observed.decided_by)
                        self.assertIsNone(observed.decided_at)
            status, headers, _ = self.request(
                mode, "POST", path, token=self.op_token,
                form={"csrf": self.op_csrf, "decision": "approve"},
                extra={"HTTP_X_AUTH_REQUEST_USER": "client@lightup.test"},
            )
            self.assertEqual(status, "303 See Other")
            self.assertEqual(headers["Location"], "/assessments")
            decided = self.store.list_risk_approvals(
                self.operator_ctx, engagement.engagement_id
            )[0]
            self.assertEqual(decided.status.value, "approved")
            self.assertEqual(decided.decided_by, self.operator_user.user_id)
            # A risk-review approval never silently issues a target grant.
            self.assertEqual(self.store.list_authorization_grants(
                self.operator_ctx, engagement.engagement_id), [])

    def test_forged_identity_cannot_submit_request_as_another_tenant(self):
        foreign_path = f"/portal/{self.client_b.client_id}/requests"
        own_path = f"/portal/{self.client_a.client_id}/requests"
        for mode in ("development", "production"):
            before = len(self.store.list_assessment_requests(self.operator_ctx))
            for key, value in SPOOFED_IDENTITIES:
                for token, csrf, expected_status in (
                    (None, self.op_csrf, "303 See Other"),
                    (self.client_token, self.client_csrf, "403 Forbidden"),
                ):
                    with self.subTest(mode=mode, key=key,
                                      identity="anonymous" if token is None else "client"):
                        status, headers, _ = self.request(
                            mode, "POST", foreign_path, token=token,
                            form={"csrf": csrf, "assets": "fixture.invalid",
                                  "risk": "1"},
                            extra={key: value},
                        )
                        self.assertEqual(status, expected_status)
                        if token is None:
                            self.assertEqual(headers["Location"], "/login")
                        self.assertEqual(
                            len(self.store.list_assessment_requests(
                                self.operator_ctx)), before
                        )
            # The same client cookie+form CSRF may only request its own scope,
            # and a submitted request never grants permission to execute.
            status, headers, _ = self.request(
                mode, "POST", own_path, token=self.client_token,
                form={"csrf": self.client_csrf, "assets": "fixture.invalid",
                      "risk": "1"},
                extra={"REMOTE_USER": "op@lightup.test"},
            )
            self.assertEqual(status, "303 See Other")
            self.assertEqual(headers["Location"], own_path[:-9])
            latest = self.store.list_assessment_requests(self.operator_ctx)[0]
            self.assertEqual(latest.client_id, self.client_a.client_id)
            self.assertEqual(latest.status.value, "submitted")
            self.assertIsNone(latest.decided_by)

    def test_genuine_operator_cookie_plus_form_csrf_remain_authoritative(self):
        # Non-authoritative identity hints must neither elevate nor disable
        # an otherwise authorized operator action.
        for mode in ("development", "production"):
            with self.subTest(mode=mode):
                status, headers, _ = self.request(
                    mode, "POST", "/clients", token=self.op_token,
                    form={"csrf": self.op_csrf, "name": f"Allowed {mode}"},
                    extra={"REMOTE_USER": "client@lightup.test",
                           "HTTP_X_FORWARDED_USER": "client@lightup.test"},
                )
                self.assertEqual(status, "303 See Other")
                self.assertEqual(headers["Location"], "/clients")
        names = {c.name for c in self.store.list_clients(self.operator_ctx)}
        self.assertEqual(names, {"Client A", "Client B", "Allowed development",
                                 "Allowed production"})


if __name__ == "__main__":
    unittest.main()
