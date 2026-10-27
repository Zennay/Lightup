import io
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

from lightup.domain import DomainStore
from lightup.webapp import create_app
from lightup.webapp.__main__ import main
from lightup.webapp.finding_exports import FindingExportWebApp
from lightup.webapp.production import create_production_app


class FindingExportEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "domain.db"
        self.store = DomainStore(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_package_factory_exposes_session_guarded_download(self):
        app = create_app(self.store)
        self.assertIsInstance(app, FindingExportWebApp)
        captured = {}
        url = "/portal/client-id/findings.csv"
        body = b"".join(app({"REQUEST_METHOD": "GET", "PATH_INFO": url,
                            "wsgi.input": io.BytesIO()},
                           lambda s, h: captured.update(status=s, headers=dict(h))))
        self.assertEqual(captured["status"], "303 See Other")
        self.assertEqual(captured["headers"]["Location"], "/login")
        self.assertEqual(body, b"")

    def test_production_factory_keeps_explicit_https_security(self):
        app = create_production_app({
            "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.test",
            "LIGHTUP_DB": str(self.db)})
        self.assertIsInstance(app, FindingExportWebApp)
        self.assertTrue(app.security.production)
        captured = {}
        body = b"".join(app({"REQUEST_METHOD": "GET",
                            "PATH_INFO": "/portal/client-id/findings.csv",
                            "REMOTE_ADDR": "203.0.113.1", "HTTP_HOST": "lightup.test",
                            "HTTP_X_FORWARDED_PROTO": "https", "wsgi.input": io.BytesIO()},
                           lambda s, h: captured.update(status=s, headers=dict(h))))
        self.assertEqual(captured["status"], "403 Forbidden")
        self.assertIn(b"Request rejected", body)
        self.assertIn("Strict-Transport-Security", captured["headers"])

    def test_production_factory_still_rejects_missing_or_unsafe_config(self):
        for env in ({}, {"LIGHTUP_DB": str(self.db)},
                    {"LIGHTUP_DB": "relative.db", "LIGHTUP_PUBLIC_ORIGIN": "https://lightup.test"},
                    {"LIGHTUP_DB": str(self.db), "LIGHTUP_PUBLIC_ORIGIN": "http://lightup.test"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                create_production_app(env)

    def test_development_launcher_uses_csv_app_and_loopback(self):
        server = MagicMock()
        server.server_port = 8766
        server.serve_forever.side_effect = KeyboardInterrupt
        cm = MagicMock()
        cm.__enter__.return_value = server
        with patch("lightup.webapp.__main__.make_server", return_value=cm) as bind, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--db", str(self.db)]), 0)
        host, port, app = bind.call_args.args
        self.assertEqual((host, port), ("127.0.0.1", 8766))
        self.assertIsInstance(app, FindingExportWebApp)

    def test_development_launcher_still_refuses_public_bind(self):
        with patch("lightup.webapp.__main__.make_server") as bind, \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--db", str(self.db), "--host", "0.0.0.0"])
        bind.assert_not_called()


if __name__ == "__main__":
    unittest.main()
