"""Synthetic ingress fixture contracts; real processes only with explicit opt-in."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scope_ingress_identity_loopback_proof as fixture  # noqa: E402


class ScopeIngressLoopbackFixtureTests(unittest.TestCase):
    def test_generated_nginx_listens_only_ipv4_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            config = fixture.nginx_config(Path(directory), 28211, 28212)
            self.assertIn("listen 127.0.0.1:28211;", config)
            self.assertIn("proxy_pass http://127.0.0.1:28212;", config)
            self.assertIn("proxy_pass_request_headers off;", config)
            self.assertIn("proxy_set_header Cookie $http_cookie;", config)
            self.assertIn("proxy_set_header Content-Length $content_length;", config)
            self.assertIn("proxy_set_header Content-Type $content_type;", config)
            self.assertIn("access_log off;", config)
            self.assertNotIn("listen 0.0.0.0:", config)
            self.assertNotIn("listen 443", config)
            self.assertNotIn("ssl_certificate", config)
            self.assertNotIn("/etc/nginx/", config)
            self.assertNotIn("include ", config)

    def test_invalid_listen_or_upstream_ports_reject_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for listen, upstream in (
                (80, 28212),
                (28211, 443),
                (0, 0),
                (28211, 28211),
                (28211, True),
                ("28211", 28212),
                (28211, 65536),
            ):
                with self.subTest(listen=listen, upstream=upstream):
                    with self.assertRaises(ValueError):
                        fixture.nginx_config(root, listen, upstream)
            with self.assertRaises(ValueError):
                fixture.nginx_config(str(root), 28211, 28212)

    @staticmethod
    def _synthetic_app(
        path: str,
        cookie: str = "",
        *,
        body: bytes = b"",
        method: str = "POST",
        hints: bool = False,
    ) -> dict:
        scope = {}
        exec(compile(fixture.FIXTURE_WSGI, "synthetic_identity_app.py", "exec"), scope)
        start = []
        env = {
            "PATH_INFO": path,
            "REQUEST_METHOD": method,
            "HTTP_COOKIE": cookie,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
        if hints:
            env["HTTP_X_ORIGINAL_COOKIE"] = fixture.SYNTHETIC_OPERATOR
            env["REMOTE_USER"] = "operator"
        encoded = b"".join(scope["application"](
            env, lambda status, headers: start.append((status, headers))
        ))
        assert start[0][0] == "200 OK"
        return json.loads(encoded)

    def test_synthetic_app_matrix_is_pure_and_nonpersisting(self):
        tests = (
            ("anonymous", "", "POST", fixture.SYNTHETIC_CSRF, "anonymous", "DENIED"),
            ("revoked", fixture.SYNTHETIC_REVOKED, "POST",
             fixture.SYNTHETIC_CSRF, "anonymous", "DENIED"),
            ("client", fixture.SYNTHETIC_CLIENT, "POST",
             fixture.SYNTHETIC_CSRF, "client", "DENIED"),
            ("operator_no_csrf", fixture.SYNTHETIC_OPERATOR, "POST",
             b"csrf=wrong", "operator", "DENIED"),
            ("operator_with_csrf", fixture.SYNTHETIC_OPERATOR, "POST",
             fixture.SYNTHETIC_CSRF, "operator", "WOULD_ALLOW"),
            ("client_portal", fixture.SYNTHETIC_CLIENT, "GET",
             b"", "client", "VISIBLE"),
        )
        for label, cookie, method, body, identity, verdict in tests:
            with self.subTest(label=label):
                response = self._synthetic_app(
                    "/portal/fixture" if label == "client_portal"
                    else "/engagements/fixture/grants",
                    cookie, method=method, body=body,
                )
                self.assertTrue(fixture._expected(response, identity, verdict))
                self.assertEqual(response["written_grants"], 0)
                self.assertEqual(response["modified_sessions"], 0)

    def test_alternate_identity_hints_deny_even_for_synthetic_operator_marker(self):
        response = self._synthetic_app(
            "/engagements/fixture/grants", "",
            body=fixture.SYNTHETIC_CSRF,
            hints=True,
        )
        self.assertEqual(response["identity"], "anonymous")
        self.assertEqual(response["verdict"], "DENIED")
        # The direct fake WSGI app observes the poisoned hint; the full
        # Nginx fixture must strip it before the app can see it.
        self.assertFalse(fixture._expected(response, "anonymous", "DENIED"))

    def test_strict_response_checker_rejects_authority_and_type_spoofing(self):
        valid = self._synthetic_app(
            "/engagements/fixture/grants", "",
            body=fixture.SYNTHETIC_CSRF,
        )
        self.assertTrue(fixture._expected(valid, "anonymous", "DENIED"))
        for key, value in (
            ("untrusted_header_forwarded", 0),
            ("remote_user_present", 0),
            ("auth_type_present", True),
            ("written_grants", False),
            ("modified_sessions", 1),
            ("identity", "operator"),
            ("verdict", "WOULD_ALLOW"),
        ):
            modified = valid.copy()
            modified[key] = value
            with self.subTest(key=key):
                self.assertFalse(fixture._expected(modified, "anonymous", "DENIED"))
        modified = valid.copy()
        modified["grant_token"] = "never-accepted"
        self.assertFalse(fixture._expected(modified, "anonymous", "DENIED"))

    def test_each_alternate_identity_header_has_independent_exact_case(self):
        self.assertEqual(len(fixture.ALTERNATE_HEADERS), 8)
        names = tuple(
            f"alternate_{value.lower().replace('-', '_')}"
            for value in fixture.ALTERNATE_HEADERS
        )
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(set(names).issubset(set(fixture.CASE_NAMES)))
        self.assertIn("alternate_combined", fixture.CASE_NAMES)
        self.assertEqual(len(fixture.CASE_NAMES), 15)

    def test_invalid_alt_header_selector_denied_before_http_object_created(self):
        with patch.object(
            fixture.http.client, "HTTPConnection",
            side_effect=AssertionError("must not even create client"),
        ):
            with self.assertRaises(RuntimeError):
                fixture._request(
                    28211, "/engagements/fixture/grants",
                    alternate_name="X-Untrusted-Identity",
                )
            with self.assertRaises(RuntimeError):
                fixture._request(
                    28211, "/engagements/fixture/grants",
                    alternate_name=True,
                )

    def test_receipts_never_mint_real_authorization(self):
        total = len(fixture.CASE_NAMES)
        for count in (0, 1, total - 1, total, True, total + 1, -1, str(total)):
            with self.subTest(count=count):
                receipt = fixture.receipt(count)
                reviewed = type(count) is int and count == total
                self.assertEqual(
                    receipt["status"], "REVIEW_ONLY" if reviewed else "HOLD"
                )
                self.assertEqual(receipt["verified_cases"], total if reviewed else 0)
                self.assertEqual(set(receipt), {
                    "status", "diagnostic_code", "verified_cases",
                    *fixture.AUTHORITY_FLAGS,
                })
                for key in fixture.AUTHORITY_FLAGS:
                    self.assertIs(receipt[key], False)

    def test_cli_rejects_hostile_arguments_without_running_processes(self):
        class HostileList(list):
            def __len__(self):
                raise AssertionError("must not inspect subclass argv")
        with patch.object(fixture, "run_fixture",
                          side_effect=AssertionError("must not spawn")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = fixture.main(HostileList())
        self.assertEqual(code, 2)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "HOLD")

    def test_cli_nonzero_exit_code_for_every_possible_review_state(self):
        for result, expected in (
            (len(fixture.CASE_NAMES), 3),
            (len(fixture.CASE_NAMES) - 1, 2),
            (0, 2),
        ):
            with self.subTest(result=result):
                output = io.StringIO()
                with patch.object(fixture, "run_fixture", return_value=result):
                    with contextlib.redirect_stdout(output):
                        code = fixture.main([])
                self.assertEqual(code, expected)
                self.assertFalse(any(
                    json.loads(output.getvalue())[key]
                    for key in fixture.AUTHORITY_FLAGS
                ))
        output = io.StringIO()
        with patch.object(fixture, "run_fixture",
                          side_effect=RuntimeError("private-sensitive-input")):
            with contextlib.redirect_stdout(output):
                code = fixture.main([])
        self.assertEqual(code, 2)
        self.assertNotIn("private-sensitive-input", output.getvalue())

    def test_actual_bad_argument_process_exits_hold_with_one_json_line(self):
        cli = ROOT / "scripts" / "scope_ingress_identity_loopback_proof.py"
        process = subprocess.run(
            [sys.executable, str(cli), "--never-launch-real-proxies"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stderr, "")
        self.assertEqual(len(process.stdout.splitlines()), 1)
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "HOLD")
        self.assertFalse(any(report[key] for key in fixture.AUTHORITY_FLAGS))

    def test_missing_real_binary_causes_atomic_hold_before_process_start(self):
        with patch.object(fixture.shutil, "which", return_value=None):
            with patch.object(fixture.subprocess, "Popen",
                              side_effect=AssertionError("must not spawn")):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = fixture.main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["verified_cases"], 0)

    @unittest.skipUnless(
        os.environ.get("LIGHTUP_REAL_NGINX_GUNICORN_LOOPBACK") == "1",
        "real disposable Nginx/Gunicorn proof requires explicit opt-in",
    )
    def test_real_disposable_proxy_and_gunicorn_on_ipv4_loopback(self):
        self.assertEqual(fixture.run_fixture(), len(fixture.CASE_NAMES))


if __name__ == "__main__":
    unittest.main()
