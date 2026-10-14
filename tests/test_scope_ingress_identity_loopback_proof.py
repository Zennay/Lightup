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
from unittest.mock import MagicMock, patch

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

    def test_untrusted_tmpdir_metacharacters_fail_before_config_generation(self):
        for value in (
            "/tmp/a b", "/tmp/a;include", "/tmp/a\\nreturn",
            "/tmp/a{bad}", "/tmp/a#comment", "/tmp/a$var",
            "/tmp/a\\tpath", "/tmp/a\\\\escaped",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    fixture.nginx_config(Path(value), 28211, 28212)

    def test_disposable_child_environment_never_inherits_execution_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            injected = {
                "GUNICORN_CMD_ARGS": "--preload --config /tmp/evil.py",
                "PYTHONPATH": "/tmp/untrusted",
                "PYTHONSTARTUP": "/tmp/evil.py",
                "PYTHONINSPECT": "1",
                "LD_PRELOAD": "/tmp/evil.so",
                "LD_LIBRARY_PATH": "/tmp/untrusted",
                "HTTP_PROXY": "http://untrusted.invalid",
                "NGINX_CONF_PATH": "/tmp/untrusted.conf",
            }
            with patch.dict(os.environ, injected):
                env = fixture._fixture_environment(root)
            self.assertIs(type(env), dict)
            self.assertEqual(env["HOME"], str(root))
            self.assertEqual(env["TMPDIR"], str(root))
            self.assertEqual(env["PYTHONNOUSERSITE"], "1")
            self.assertEqual(env["LANG"], "C")
            self.assertIn("/usr/bin", env["PATH"])
            self.assertEqual(set(env), {
                "HOME", "TMPDIR", "PATH", "LANG", "PYTHONNOUSERSITE",
            })
            for key in injected:
                self.assertNotIn(key, env)
            env["GUNICORN_CMD_ARGS"] = "mutated"
            self.assertNotIn("GUNICORN_CMD_ARGS", fixture._fixture_environment(root))

    def test_subprocess_environment_requires_plain_absolute_path(self):
        for root in ("not-a-path", Path("relative"), None):
            with self.subTest(root=root):
                with self.assertRaises(ValueError):
                    fixture._fixture_environment(root)

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
        client_names = tuple(
            f"client_spoof_{value.lower().replace('-', '_')}"
            for value in fixture.ALTERNATE_HEADERS
        )
        self.assertEqual(len(client_names), len(set(client_names)))
        self.assertTrue(set(client_names).issubset(set(fixture.CASE_NAMES)))
        self.assertFalse(set(client_names).intersection(set(names)))
        self.assertIn("alternate_combined", fixture.CASE_NAMES)
        self.assertEqual(len(fixture.CASE_NAMES), 23)

    def test_synthetic_client_with_untrusted_operator_hints_never_elevates(self):
        response = self._synthetic_app(
            "/engagements/fixture/grants",
            fixture.SYNTHETIC_CLIENT,
            body=fixture.SYNTHETIC_CSRF,
            hints=True,
        )
        self.assertEqual(response["identity"], "client")
        self.assertEqual(response["verdict"], "DENIED")
        self.assertEqual(response["written_grants"], 0)
        self.assertFalse(fixture._expected(response, "client", "DENIED"))

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

    def test_nginx_binary_lookup_uses_fixed_local_system_path(self):
        with patch.object(fixture.shutil, "which", return_value=None) as lookup:
            with self.assertRaises(RuntimeError):
                fixture.run_fixture()
        lookup.assert_called_once_with(
            "nginx", path=fixture.SAFE_EXECUTABLE_PATH,
        )
        self.assertEqual(
            fixture.SAFE_EXECUTABLE_PATH,
            fixture._fixture_environment(Path("/tmp"))["PATH"],
        )

    def test_missing_real_binary_causes_atomic_hold_before_process_start(self):
        with patch.object(fixture.shutil, "which", return_value=None):
            with patch.object(fixture.subprocess, "Popen",
                              side_effect=AssertionError("must not spawn")):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = fixture.main([])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["verified_cases"], 0)

    @staticmethod
    def _mock_proxied_outcome(
        port, path, *, method="GET", cookie=None, alternates=False,
        alternate_name=None, body=None,
    ):
        # Models only the already defined fake WSGI outcomes, not a real
        # ingress request; prove launch, matrix and cleanup orchestration.
        if path == "/portal/fixture":
            identity, verdict = "client", "VISIBLE"
        elif cookie == fixture.SYNTHETIC_OPERATOR:
            identity = "operator"
            verdict = "WOULD_ALLOW" if (
                method == "POST" and body == fixture.SYNTHETIC_CSRF
            ) else "DENIED"
        elif cookie == fixture.SYNTHETIC_CLIENT:
            identity, verdict = "client", "DENIED"
        else:
            identity, verdict = "anonymous", "DENIED"
        return {
            "identity": identity, "verdict": verdict,
            "untrusted_header_forwarded": False,
            "remote_user_present": False, "auth_type_present": False,
            "written_grants": 0, "modified_sessions": 0,
        }

    def _mock_run_fixture(self, *, poison=False):
        child1, child2 = MagicMock(), MagicMock()
        outcome = self._mock_proxied_outcome
        def simulate(*args, **kwargs):
            result = outcome(*args, **kwargs)
            if poison and kwargs.get("alternate_name") == "Authorization":
                result["untrusted_header_forwarded"] = True
            return result
        with patch.object(fixture.shutil, "which",
                          return_value="/usr/sbin/nginx"), \
             patch.object(fixture.importlib.util, "find_spec",
                          return_value=object()), \
             patch.object(fixture, "_free_port",
                          side_effect=(28211, 28212)), \
             patch.object(fixture.subprocess, "run") as check, \
             patch.object(fixture.subprocess, "Popen",
                          side_effect=(child1, child2)) as spawn, \
             patch.object(fixture, "_wait_listening") as ready, \
             patch.object(fixture, "_stop") as stop, \
             patch.object(fixture, "_request", side_effect=simulate) as requests, \
             patch.dict(os.environ, {
                 "GUNICORN_CMD_ARGS": "--preload",
                 "PYTHONPATH": "/tmp/unsafe",
                 "LD_PRELOAD": "/tmp/unsafe.so",
             }):
            check.return_value.returncode = 0
            if poison:
                with self.assertRaises(RuntimeError):
                    fixture.run_fixture()
            else:
                self.assertEqual(fixture.run_fixture(), len(fixture.CASE_NAMES))
            self.assertEqual(check.call_count, 1)
            self.assertEqual(spawn.call_count, 2)
            self.assertEqual(ready.call_count, 2)
            self.assertEqual(stop.call_count, 2)
            self.assertIs(stop.call_args_list[0].args[0], child2)
            self.assertIs(stop.call_args_list[1].args[0], child1)
            self.assertGreaterEqual(requests.call_count, 1)
            envs = [check.call_args.kwargs["env"]] + [
                call.kwargs["env"] for call in spawn.call_args_list
            ]
            for env in envs:
                self.assertEqual(set(env), {
                    "HOME", "TMPDIR", "PATH", "LANG", "PYTHONNOUSERSITE",
                })
                self.assertEqual(env["LANG"], "C")
                self.assertEqual(env["PYTHONNOUSERSITE"], "1")
                self.assertNotIn("GUNICORN_CMD_ARGS", env)
                self.assertNotIn("PYTHONPATH", env)
                self.assertNotIn("LD_PRELOAD", env)
                self.assertTrue(env["HOME"].startswith("/"))
            self.assertTrue(
                all(env == envs[0] for env in envs[1:]),
                "precheck and both children must use identical isolated env",
            )
            self.assertEqual(
                spawn.call_args_list[0].args[0][4],
                "127.0.0.1:28211",
            )
            self.assertIn(
                "daemon off;",
                spawn.call_args_list[1].args[0][-1],
            )
            return requests.call_count

    def test_cleanup_attempts_every_child_and_never_claims_success_on_error(self):
        first, second = MagicMock(), MagicMock()
        def stop_one(process):
            if process is second:
                raise OSError("injected local termination failure")
        with patch.object(fixture, "_stop", side_effect=stop_one) as stop:
            with self.assertRaisesRegex(RuntimeError, "cleanup incomplete"):
                fixture._stop_all([first, second])
        self.assertEqual(stop.call_count, 2)
        self.assertIs(stop.call_args_list[0].args[0], second)
        self.assertIs(stop.call_args_list[1].args[0], first)

    def test_cleanup_empty_process_list_is_safe(self):
        fixture._stop_all([])

    def test_full_synthetic_launch_orchestration_checks_all_23_cases(self):
        self.assertEqual(self._mock_run_fixture(), len(fixture.CASE_NAMES))

    def test_synthetic_launch_aborts_and_cleans_both_processes_on_spoof(self):
        # Any forbidden header arriving upstream means no partial green
        # even if all preceding cases seemed harmless.
        self.assertGreater(self._mock_run_fixture(poison=True), 0)

    @unittest.skipUnless(
        os.environ.get("LIGHTUP_REAL_NGINX_GUNICORN_LOOPBACK") == "1",
        "real disposable Nginx/Gunicorn proof requires explicit opt-in",
    )
    def test_real_disposable_proxy_and_gunicorn_on_ipv4_loopback(self):
        self.assertEqual(fixture.run_fixture(), len(fixture.CASE_NAMES))


if __name__ == "__main__":
    unittest.main()
