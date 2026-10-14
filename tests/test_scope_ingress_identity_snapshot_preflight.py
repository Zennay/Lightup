"""Offline, synthetic-only acceptance of scope ingress identity snapshot preflight."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import scope_ingress_identity_snapshot_preflight as preflight  # noqa: E402

NGINX = b"""# configuration file /etc/nginx/nginx.conf:
server {
    listen 443 ssl;
    server_name fixture.invalid;
    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_pass_request_headers off;
        proxy_set_header Host $http_host;
        proxy_set_header Cookie $http_cookie;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
"""
GUNICORN = b"""bind = '127.0.0.1:8766'
forwarded_allow_ips = ''
secure_scheme_headers = {}
worker_class = 'sync'
"""


class IngressIdentitySnapshotPreflightTests(unittest.TestCase):
    def assert_hold(self, nginx=NGINX, gunicorn=GUNICORN):
        out = preflight.review(nginx, gunicorn)
        self.assertEqual(out["decision"], "HOLD")
        self.assertEqual(out["diagnostic_code"], "SNAPSHOT_REJECTED")
        self.assertIsNone(out["nginx_sha256"])
        self.assertIsNone(out["gunicorn_sha256"])
        self.assertFalse(any(out[key] for key in preflight.FLAGS))
        self.assertEqual(set(out), {
            "decision", "diagnostic_code", "nginx_sha256", "gunicorn_sha256",
            *preflight.FLAGS,
        })

    def test_minimal_synthetic_positive_is_never_authorization(self):
        out = preflight.review(NGINX, GUNICORN)
        self.assertEqual(out["decision"], "REVIEW_ONLY")
        self.assertEqual(out["diagnostic_code"], "STATIC_SHAPE_MATCHED")
        self.assertEqual(len(out["nginx_sha256"]), 64)
        self.assertEqual(len(out["gunicorn_sha256"]), 64)
        self.assertFalse(any(out[key] for key in preflight.FLAGS))

    def test_existing_nginx_template_is_not_misrepresented_as_proven_ingress(self):
        # As shipped, proxy_pass_request_headers is not disabled. A WSGI
        # rejection test alone is not installed proxy transformation proof.
        existing_shape = NGINX.replace(b"proxy_pass_request_headers off;", b"")
        self.assert_hold(existing_shape)

    def test_forwarded_alternate_cookies_and_identity_hints_are_rejected(self):
        for name in (
            b"X-Forwarded-Cookie", b"X-Original-Cookie",
            b"X-Auth-Request-Cookie", b"Cookie2", b"Authorization",
            b"X-Forwarded-User", b"X-Auth-Request-User",
            b"Remote-User",
        ):
            with self.subTest(header=name):
                variant = NGINX.replace(
                    b"proxy_set_header Cookie $http_cookie;",
                    b"proxy_set_header Cookie $http_cookie;\n"
                    b"proxy_set_header " + name + b" $http_cookie;",
                )
                self.assert_hold(variant)

    def test_cookie_must_be_direct_canonical_request_header(self):
        self.assert_hold(NGINX.replace(
            b"proxy_set_header Cookie $http_cookie;",
            b"proxy_set_header Cookie $http_x_original_cookie;",
        ))
        self.assert_hold(NGINX.replace(
            b"proxy_set_header Cookie $http_cookie;",
            b"proxy_set_header Cookie $http_cookie;\n"
            b"proxy_set_header Cookie $http_cookie;",
        ))

    def test_conflicting_or_remote_upstreams_hold(self):
        for bad in (
            NGINX.replace(b"127.0.0.1:8766", b"198.51.100.17:8766"),
            NGINX.replace(b"proxy_pass http://127.0.0.1:8766;",
                          b"proxy_pass http://127.0.0.1:8766;\n"
                          b"proxy_pass http://127.0.0.1:8766;"),
            NGINX.replace(b"proxy_pass_request_headers off;",
                          b"proxy_pass_request_headers on;"),
            NGINX.replace(b"location / {", b"location / {\nif ($http_cookie) { return 200; }"),
        ):
            with self.subTest(bad=bad[-120:]):
                self.assert_hold(bad)

    def test_proxy_transform_features_and_unknown_includes_hold(self):
        for directive in (
            b"include /etc/nginx/sites-enabled/*;",
            b"rewrite ^ /login last;",
            b"auth_request /subrequest;",
            b"set $http_cookie $http_x_forwarded_cookie;",
            b"real_ip_header X-Forwarded-For;",
            b"lua_need_request_body on;",
        ):
            with self.subTest(directive=directive):
                self.assert_hold(NGINX.replace(
                    b"server_name fixture.invalid;",
                    b"server_name fixture.invalid;\n    " + directive,
                ))

    def test_unrecognized_config_modules_never_promote_static_review(self):
        # Unknown extension directives may mutate request Cookie/identity
        # even if a superficial list of known dangerous directives misses it.
        for rogue in (
            b"more_set_input_headers 'Cookie: synthetic';",
            b"proxy_cookie_path / /;",
            b"custom_auth_bridge X-Original-Cookie;",
            b"mod_security on;",
        ):
            with self.subTest(rogue=rogue):
                self.assert_hold(NGINX.replace(
                    b"server_name fixture.invalid;",
                    b"server_name fixture.invalid;\\n    " + rogue,
                ))
        for rogue in (
            b"raw_env = ['AUTH_TYPE=operator']",
            b"forwarder_headers = ['REMOTE_USER']",
            b"wsgi_app = 'untrusted:app'",
            b"proxy_protocol = True",
        ):
            with self.subTest(rogue=rogue):
                self.assert_hold(NGINX, GUNICORN + rogue + b"\\n")

    def test_checked_in_nginx_example_is_not_treated_as_effective_proof(self):
        # It does not explicitly disable implicit request header passthrough.
        template = (ROOT / "deploy" / "nginx.conf.example").read_bytes()
        self.assertNotIn(b"proxy_pass_request_headers off;", template)
        self.assert_hold(b"# configuration file /etc/nginx/nginx.conf:\\n" + template)

    def test_spoofed_provenance_comments_cannot_approve_unsafe_header_shape(self):
        bad = NGINX.replace(
            b"proxy_pass_request_headers off;",
            b"# proxy_pass_request_headers off;\n"
            b"proxy_pass_request_headers on;",
        )
        self.assert_hold(bad)
        self.assert_hold(NGINX.replace(b"# configuration file ", b"# copied template "))

    def test_gunicorn_remote_bind_proxy_trust_or_ambiguous_printed_settings_hold(self):
        for bad in (
            GUNICORN.replace(b"127.0.0.1:8766", b"0.0.0.0:8766"),
            GUNICORN.replace(b"forwarded_allow_ips = ''",
                             b"forwarded_allow_ips = '*'"),
            GUNICORN.replace(b"secure_scheme_headers = {}",
                             b"secure_scheme_headers = {'X-Forwarded-Proto': 'https'}"),
            GUNICORN.replace(b"worker_class = 'sync'", b"worker_class = 'gevent'"),
            GUNICORN + b"bind = '127.0.0.1:8766'\n",
            GUNICORN.replace(b"bind = '127.0.0.1:8766'", b"bind = eval('evil')"),
        ):
            with self.subTest(config=bad[-80:]):
                self.assert_hold(NGINX, bad)

    def test_bounded_bytes_and_noncanonical_types_hold(self):
        self.assert_hold(b"")
        self.assert_hold(NGINX + b"\x00")
        self.assert_hold(NGINX + b"\xff")
        self.assert_hold(NGINX + b"x" * preflight.MAX_SNAPSHOT_BYTES)
        self.assert_hold(NGINX, GUNICORN + b"\xff")
        self.assert_hold("not bytes", GUNICORN)
        self.assert_hold(NGINX, bytearray(GUNICORN))

    def test_no_network_or_process_side_effects_in_pure_checker(self):
        import socket
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            out = preflight.review(NGINX, GUNICORN)
        self.assertEqual(out["decision"], "REVIEW_ONLY")

    def test_cli_local_files_use_nonzero_exit_and_exact_single_json_line(self):
        with tempfile.TemporaryDirectory() as directory:
            nginx = Path(directory) / "nginx.txt"
            gunicorn = Path(directory) / "gunicorn.txt"
            nginx.write_bytes(NGINX)
            gunicorn.write_bytes(GUNICORN)
            cmd = [
                sys.executable, str(ROOT / "scripts" / "scope_ingress_identity_snapshot_preflight.py"),
                "--nginx-effective", str(nginx),
                "--gunicorn-effective", str(gunicorn),
            ]
            run = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 3)
            self.assertEqual(run.stderr, "")
            self.assertEqual(len(run.stdout.splitlines()), 1)
            receipt = json.loads(run.stdout)
            self.assertEqual(receipt["decision"], "REVIEW_ONLY")
            self.assertFalse(any(receipt[key] for key in preflight.FLAGS))
            gunicorn.write_bytes(b"malformed")
            reject = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(reject.returncode, 2)
            self.assertEqual(len(reject.stdout.splitlines()), 1)
            self.assertFalse(any(json.loads(reject.stdout)[key] for key in preflight.FLAGS))

    def test_invalid_cli_never_echoes_sensitive_arguments(self):
        secret = "private-marker-cannot-appear-in-receipt"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = preflight.main(["--nginx-effective", secret])
        self.assertEqual(result, 2)
        self.assertNotIn(secret, output.getvalue())
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt["decision"], "HOLD")
        self.assertFalse(any(receipt[key] for key in preflight.FLAGS))

    def test_hostile_argv_container_rejected_without_magic_methods(self):
        class HostileList(list):
            def __len__(self):
                raise AssertionError("must not query untrusted argv")
            def __iter__(self):
                raise AssertionError("must not iterate untrusted argv")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = preflight.main(HostileList())
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["decision"], "HOLD")

    def test_receipt_flags_are_fresh_after_caller_mutation(self):
        first = preflight.review(NGINX, GUNICORN)
        for key in preflight.FLAGS:
            first[key] = True
        second = preflight.review(NGINX, GUNICORN)
        denied = preflight.review(b"bad", GUNICORN)
        for key in preflight.FLAGS:
            self.assertIs(second[key], False)
            self.assertIs(denied[key], False)


if __name__ == "__main__":
    unittest.main()
