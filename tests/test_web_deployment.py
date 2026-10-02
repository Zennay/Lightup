import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import DomainStore
from lightup.webapp import create_app
from lightup.webapp.production import create_production_app
from lightup.webapp.security import RequestRejected, WebSecurity


class SecurityBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.security = WebSecurity("https://lightup.example.test")

    def env(self, **updates):
        return {"HTTP_HOST": "lightup.example.test", "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_PROTO": "https", "REQUEST_METHOD": "GET", **updates}

    def test_exact_proxy_and_host_allowed(self):
        self.security.validate(self.env())
        self.security.validate(self.env(HTTP_HOST="LIGHTUP.EXAMPLE.TEST:443"))

    def test_invalid_configuration_is_rejected(self):
        for value in ("http://lightup.test", "", "https://a/path", "https://a?b",
                      "https://user:pass@a", "https://a:0", "https://a:70000",
                      "https://a,evil.test", "https://a\\evil.test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                WebSecurity(value)
        with self.assertRaises(ValueError):
            WebSecurity("https://lightup.test", "0.0.0.0")

    def test_host_and_forwarded_host_cannot_select_origin(self):
        for host in ("evil.test", "", "lightup.example.test.evil.test",
                     "lightup.example.test:444", "lightup.example.test@evil.test",
                     "lightup.example.test,evil.test"):
            with self.subTest(host=host), self.assertRaises(RequestRejected):
                self.security.validate(self.env(HTTP_HOST=host,
                    HTTP_X_FORWARDED_HOST="lightup.example.test"))
        self.security.validate(self.env(HTTP_X_FORWARDED_HOST="evil.test"))

    def test_proxy_spoofing_and_plaintext_fail_closed(self):
        for values in ({"REMOTE_ADDR": "192.0.2.8", "HTTP_X_FORWARDED_FOR": "127.0.0.1"},
                       {"REMOTE_ADDR": ""}, {"HTTP_X_FORWARDED_PROTO": ""},
                       {"HTTP_X_FORWARDED_PROTO": "http"},
                       {"HTTP_X_FORWARDED_PROTO": "https,http"}):
            with self.subTest(values=values), self.assertRaises(RequestRejected):
                self.security.validate(self.env(**values))

    def test_post_requires_exact_origin_including_login(self):
        for value in ("null", "https://evil.test", "http://lightup.example.test",
                      "https://lightup.example.test:444", "https://lightup.example.test/path"):
            with self.subTest(value=value), self.assertRaises(RequestRejected):
                self.security.validate(self.env(REQUEST_METHOD="POST", HTTP_ORIGIN=value))
        self.security.validate(self.env(REQUEST_METHOD="POST",
                                       HTTP_ORIGIN="https://lightup.example.test:443"))

    def test_absent_origin_needs_same_origin_referer(self):
        with self.assertRaises(RequestRejected):
            self.security.validate(self.env(REQUEST_METHOD="POST"))
        self.security.validate(self.env(REQUEST_METHOD="POST",
            HTTP_REFERER="https://lightup.example.test/login?next=portal"))
        with self.assertRaises(RequestRejected):
            self.security.validate(self.env(REQUEST_METHOD="POST",
                HTTP_REFERER="https://evil.test/login"))

    def test_bad_origin_cannot_be_overridden_by_good_referer(self):
        with self.assertRaises(RequestRejected):
            self.security.validate(self.env(REQUEST_METHOD="POST", HTTP_ORIGIN="null",
                HTTP_REFERER="https://lightup.example.test/login"))

    def test_cross_site_fetch_metadata_rejected(self):
        with self.assertRaises(RequestRejected):
            self.security.validate(self.env(REQUEST_METHOD="POST",
                HTTP_ORIGIN="https://lightup.example.test", HTTP_SEC_FETCH_SITE="cross-site"))

    def test_development_rejects_dns_rebinding_and_foreign_forms(self):
        dev = WebSecurity()
        for host in ("localhost:8766", "127.0.0.1:8766", "[::1]:8766"):
            dev.validate({"HTTP_HOST": host})
        with self.assertRaises(RequestRejected):
            dev.validate({"HTTP_HOST": "rebinding.example"})
        with self.assertRaises(RequestRejected):
            dev.validate({"HTTP_HOST": "localhost:8766", "REQUEST_METHOD": "POST",
                          "HTTP_ORIGIN": "https://evil.test"})

    def test_rejection_happens_before_reading_body_or_session(self):
        store = Mock()
        stream = Mock()
        app = create_app(store, self.security)
        env = self.env(REQUEST_METHOD="POST", HTTP_ORIGIN="https://evil.test",
                       PATH_INFO="/login", **{"wsgi.input": stream})
        captured = {}
        b"".join(app(env, lambda s, h: captured.update(status=s, headers=dict(h))))
        self.assertEqual(captured["status"], "403 Forbidden")
        self.assertEqual(captured["headers"]["Cache-Control"], "no-store")
        stream.read.assert_not_called()
        self.assertEqual(store.mock_calls, [])


class ProductionAppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "web.db")
        self.app = create_production_app({"LIGHTUP_PUBLIC_ORIGIN": "https://lightup.example.test",
                                         "LIGHTUP_DB": self.db})
        self.user = self.app.store.bootstrap_operator("op@test.example", "Operator",
                                                       "deployment-test-password")

    def request(self, path, form=None, cookie=None, **updates):
        raw = urlencode(form or {}).encode()
        env = {"HTTP_HOST": "lightup.example.test", "REMOTE_ADDR": "127.0.0.1",
               "HTTP_X_FORWARDED_PROTO": "https",
               "HTTP_ORIGIN": "https://lightup.example.test",
               "REQUEST_METHOD": "POST" if form is not None else "GET",
               "PATH_INFO": path, "CONTENT_LENGTH": str(len(raw)),
               "CONTENT_TYPE": "application/x-www-form-urlencoded",
               "wsgi.input": io.BytesIO(raw), **updates}
        if cookie:
            env["HTTP_COOKIE"] = cookie
        out = {}
        body = b"".join(self.app(env, lambda s, h: out.update(status=s, headers=dict(h))))
        return out["status"], out["headers"], body

    def test_secure_cookie_login_and_logout_revoke(self):
        status, headers, _ = self.request("/login",
            {"email": "op@test.example", "password": "deployment-test-password"})
        self.assertEqual(status, "303 See Other")
        cookie = headers["Set-Cookie"]
        self.assertIn("; Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=31536000")
        token = cookie.split("=", 1)[1].split(";")[0]
        _, csrf = self.app.store.session_context(token)
        status, headers, _ = self.request("/logout", {"csrf": csrf}, cookie)
        self.assertEqual(status, "303 See Other")
        self.assertIn("; Secure", headers["Set-Cookie"])
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertIsNone(self.app.store.session_context(token))

    def test_same_origin_does_not_replace_csrf(self):
        token, _ = self.app.store.create_session(self.user.user_id)
        status, _, _ = self.request("/clients", {"name": "Denied"},
                                     "lightup_session=" + token)
        self.assertEqual(status, "403 Forbidden")
        context = self.app.store.context_for_user(self.user.user_id)
        self.assertEqual(self.app.store.list_clients(context), [])

    def test_factory_requires_configuration_before_database_creation(self):
        for env in ({}, {"LIGHTUP_PUBLIC_ORIGIN": "https://lightup.test", "LIGHTUP_DB": "relative.db"},
                    {"LIGHTUP_PUBLIC_ORIGIN": "http://lightup.test", "LIGHTUP_DB": self.db}):
            with patch("lightup.webapp.production.DomainStore") as store:
                with self.assertRaises(ValueError):
                    create_production_app(env)
                store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
