"""Synthetic, opt-in #1154 ingress proof; no production configuration changes."""
import contextlib
import http.client
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app

SOURCE = (Path(__file__).resolve().parents[1] / "scripts"
          / "scope_nginx_loopback_method_acceptance_20261015.py")
spec = importlib.util.spec_from_file_location("scope_1154_loopback", SOURCE)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ScopeIngressMethodE2ETest(unittest.TestCase):
    def setUp(self):
        self.template = check.TEMPLATE.read_text(encoding="utf-8")

    def test_disposable_nginx_environment_excludes_runner_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {
                "GITHUB_TOKEN": "synthetic-never-inherit",
                "LIGHTUP_DB": "/synthetic/production.db",
                "AWS_ACCESS_KEY_ID": "synthetic-example",
                "HTTP_PROXY": "http://synthetic.invalid:3128",
            }):
                config = check._fixture_env(Path(folder))
            self.assertEqual(
                config,
                {"HOME": str(folder), "TMPDIR": str(folder),
                 "LANG": "C", "LC_ALL": "C"}
            )
            for secret in (
                "GITHUB_TOKEN", "LIGHTUP_DB", "AWS_ACCESS_KEY_ID",
                "HTTP_PROXY",
            ):
                self.assertNotIn(secret, config)

    def test_ephemeral_render_preserves_only_loopback_network(self):
        with tempfile.TemporaryDirectory() as folder:
            config = check.render_loopback_config(
                self.template, 18111, 18112, Path(folder)
            )
        self.assertIn("listen 127.0.0.1:18111;", config)
        self.assertIn("proxy_pass http://127.0.0.1:18112;", config)
        self.assertNotIn("listen 443 ssl;", config)
        self.assertNotIn("/etc/letsencrypt", config)
        self.assertNotIn("server_name lightup.example.com;", config)
        self.assertNotIn("proxy_method GET;", config)

    def test_rejects_unexpected_bind_upstream_or_config_include(self):
        for modified in (
            self.template.replace("127.0.0.1:8766", "192.0.2.1:8766"),
            self.template.replace("listen 443 ssl;", "listen 0.0.0.0:443 ssl;"),
            self.template + "\nserver { listen 80; }",
            self.template + "\nlocation /side { proxy_pass http://192.0.2.1; }",
            self.template + "\ninclude /tmp/untrusted.conf;",
            self.template + "\nproxy_method POST;",
            self.template.replace("        proxy_read_timeout 35s;",
                                  "        mirror /external;\n        proxy_read_timeout 35s;"),
            self.template.replace("        proxy_read_timeout 35s;",
                                  "        auth_request /verify;\n        proxy_read_timeout 35s;"),
            self.template.replace("        proxy_read_timeout 35s;",
                                  "        resolver 1.1.1.1;\n        proxy_read_timeout 35s;"),
        ):
            with self.subTest(change=modified[-60:]), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError):
                    check.render_loopback_config(modified, 18001, 18002, Path(folder))

    def test_closed_world_directive_order_count_and_scope(self):
        # Even whitelisted text can become unsafe after Nginx scoping and
        # inheritance changes. A set-membership allowlist alone is insufficient.
        protected = self.template.replace(
            "        proxy_request_buffering on;",
            "".join(f'        proxy_set_header {name} "";\n'
                    for name in check.OVERRIDE_NAMES)
            + "        proxy_request_buffering on;",
        )
        mutations = {
            "remove_host_header": protected.replace(
                "        proxy_set_header Host $http_host;\n", ""),
            "duplicate_host_header": protected.replace(
                "        proxy_set_header Host $http_host;",
                "        proxy_set_header Host $http_host;\n"
                "        proxy_set_header Host $http_host;"),
            "swap_forwarding_order": protected.replace(
                "        proxy_set_header X-Forwarded-For $remote_addr;\n"
                '        proxy_set_header X-Forwarded-Host "";',
                '        proxy_set_header X-Forwarded-Host "";\n'
                "        proxy_set_header X-Forwarded-For $remote_addr;"),
            "move_strip_into_server": protected.replace(
                '        proxy_set_header X-HTTP-Method-Override "";\n', ""
            ).replace(
                "    location / {",
                '    proxy_set_header X-HTTP-Method-Override "";\n'
                "    location / {"),
            "move_strip_after_location": protected.replace(
                '        proxy_set_header X-HTTP-Method-Override "";\n', ""
            ).replace(
                "    }\n}",
                '    }\n    proxy_set_header X-HTTP-Method-Override "";\n}'),
            "duplicate_strip": protected.replace(
                '        proxy_set_header X-HTTP-Method-Override "";',
                '        proxy_set_header X-HTTP-Method-Override "";\n'
                '        proxy_set_header X-HTTP-Method-Override "";'),
            "remove_body_buffering": protected.replace(
                "        proxy_request_buffering on;\n", ""),
            "move_proxy_connect_timeout": protected.replace(
                "        proxy_connect_timeout 5s;\n", ""
            ).replace(
                "        proxy_pass http://127.0.0.1:8766;",
                "        proxy_connect_timeout 5s;\n"
                "        proxy_pass http://127.0.0.1:8766;"),
        }
        with tempfile.TemporaryDirectory() as root:
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    self.assertNotEqual(payload, protected)
                    with self.assertRaises(ValueError):
                        check.render_loopback_config(
                            payload, 18011, 18012, Path(root))
            # Both the unmodified original and the independent owner-style
            # candidate (headers inserted before X-Forwarded-Ssl) remain valid.
            self.assertIn("listen 127.0.0.1:18011;",
                          check.render_loopback_config(
                              self.template, 18011, 18012, Path(root)))
            owner_style = self.template.replace(
                '        proxy_set_header X-Forwarded-Ssl "";',
                "".join(f'        proxy_set_header {name} "";\n'
                        for name in check.OVERRIDE_NAMES)
                + '        proxy_set_header X-Forwarded-Ssl "";',
            )
            self.assertIn("listen 127.0.0.1:18011;",
                          check.render_loopback_config(
                              owner_style, 18011, 18012, Path(root)))

    def test_every_baseline_directive_is_required_exactly_once(self):
        # Property-style mutation sweep of the actual maintained template.
        # Every directive in the baseline must survive; a whitelisted
        # directive duplicated anywhere is still an unsupported candidate.
        with tempfile.TemporaryDirectory() as tmp:
            for position, directive in enumerate(check._BASE_DIRECTIVES):
                with self.subTest(position=position, directive=directive):
                    self.assertIn(directive, self.template)
                    removed = self.template.replace(directive, "", 1)
                    doubled = self.template.replace(
                        directive, directive + "\n" + directive, 1)
                    for changed in (removed, doubled):
                        with self.assertRaises(ValueError):
                            check.render_loopback_config(
                                changed, 17991, 17992, Path(tmp))

    def test_runtime_output_never_confers_permission_on_holds(self):
        with patch.object(check, "TEMPLATE") as fake_template:
            fake_template.read_text.return_value = self.template
            with patch.object(check.shutil, "which", return_value=None):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = check.main()
        receipt = json.loads(buf.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertEqual(receipt["reason"], "nginx_unavailable")
        for field, false_value in check.FALSE_FLAGS.items():
            self.assertIs(false_value, False)
            self.assertIs(receipt[field], False)
        self.assertEqual(set(receipt), {"verdict", "reason", *check.FALSE_FLAGS})

    def test_review_only_requires_negative_mutant_to_be_detected(self):
        # Isolate the CLI truth table from Nginx availability; the real
        # subprocess positive/negative witness is separately tested above.
        with patch.object(check, "TEMPLATE") as fake_template, \
             patch.object(check.shutil, "which", return_value="/lab/nginx"):
            fake_template.read_text.return_value = self.template
            for candidate, mutation, expected, exit_code in (
                (True, False, "REVIEW_ONLY", 3),
                (True, True, "HOLD", 2),
                (False, False, "HOLD", 2),
            ):
                with self.subTest(candidate=candidate, mutation=mutation), \
                     patch.object(check, "run_probe",
                                  side_effect=[candidate, mutation]) as probe:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = check.main()
                receipt = json.loads(out.getvalue())
                self.assertEqual(code, exit_code)
                self.assertEqual(receipt["verdict"], expected)
                self.assertTrue(all(receipt[k] is False for k in check.FALSE_FLAGS))
                self.assertEqual(probe.call_count, 2 if candidate else 1)

    def test_malformed_upstream_receipts_always_fail_closed(self):
        good = {
            "method": "POST", "path": "/__scope_method_fixture__",
            "body": "x", "override_headers": {},
        }
        self.assertTrue(check._receipt_is_exact(good, "POST"))
        bad = [None, False, 1, [], (), "", "APPROVED",
               {**good, "method": True},
               {**good, "path": True},
               {**good, "body": True},
               {**good, "override_headers": []},
               {**good, "override_headers": {"X-Method-Override": "GET"}},
               {**good, "authorizes_targets": True},
               {key: val for key, val in good.items() if key != "body"}]
        for receipt in bad:
            with self.subTest(receipt=repr(receipt)):
                self.assertFalse(check._receipt_is_exact(receipt, "POST"))
        self.assertFalse(check._receipt_is_exact(good, "GET"))

    def test_http_upstream_disconnect_is_opaque_hold(self):
        # A truncated upstream response must never leak the HTTP client's
        # diagnostic to stderr or become an authorization-looking result.
        with patch.object(check, "TEMPLATE") as temp, \
             patch.object(check.shutil, "which", return_value="/lab/nginx"), \
             patch.object(check, "run_probe",
                          side_effect=http.client.IncompleteRead(b"secret!")):
            temp.read_text.return_value = self.template
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = check.main()
        receipt = json.loads(out.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(receipt["verdict"], "HOLD")
        self.assertTrue(all(receipt[k] is False for k in check.FALSE_FLAGS))
        self.assertNotIn("secret", out.getvalue())

    def test_owner_style_header_placement_is_proved_by_real_nginx(self):
        # PR #1155 places the four strips before X-Forwarded-Ssl. The earlier
        # protected candidate exercised a different but valid placement.
        # Verify the owner-style ordering through real network traffic too.
        if not shutil.which("nginx"):
            self.skipTest("nginx unavailable; owner-style traffic not proved")
        candidate = self.template.replace(
            '        proxy_set_header X-Forwarded-Ssl "";',
            "        # Client-supplied method overrides are not trusted.\n"
            + "".join(f'        proxy_set_header {name} "";\n'
                      for name in check.OVERRIDE_NAMES)
            + '        proxy_set_header X-Forwarded-Ssl "";',
        )
        self.assertTrue(check.run_probe(candidate))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "owner-style-synthetic.conf"
            path.write_text(candidate, encoding="utf-8")
            receipt = io.StringIO()
            with contextlib.redirect_stdout(receipt):
                code = check.main(("--candidate-file", str(path)))
        self.assertEqual(code, 3)
        report = json.loads(receipt.getvalue())
        self.assertEqual(report["verdict"], "REVIEW_ONLY")
        self.assertTrue(all(report[k] is False for k in check.FALSE_FLAGS))

    def test_candidate_file_cli_is_read_only_and_non_authorizing(self):
        if not shutil.which("nginx"):
            self.skipTest("real nginx needed for a candidate-file receipt")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-nginx.conf"
            fixed = self.template.replace(
                "        proxy_request_buffering on;",
                "".join(f'        proxy_set_header {name} "";\n'
                        for name in check.OVERRIDE_NAMES)
                + "        proxy_request_buffering on;",
            )
            path.write_text(fixed, encoding="utf-8")
            before = path.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = check.main(("--candidate-file", str(path)))
            receipt = json.loads(output.getvalue())
            self.assertEqual(result, 3)
            self.assertEqual(receipt["verdict"], "REVIEW_ONLY")
            self.assertTrue(all(receipt[k] is False for k in check.FALSE_FLAGS))
            self.assertEqual(path.read_bytes(), before, "CLI must never write candidate")

            # The same real Nginx probe on one removed filter MUST HOLD.
            removed = fixed.replace(
                f'        proxy_set_header {check.OVERRIDE_NAMES[0]} "";\n', ""
            )
            path.write_text(removed, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = check.main(("--candidate-file", str(path)))
            self.assertEqual(result, 2)
            self.assertEqual(json.loads(output.getvalue())["verdict"], "HOLD")

    def test_candidate_file_refuses_bad_input_without_content_echo(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "fictional_secret_candidate.conf"
            original.write_text("THIS_IS_NOT_A_REAL_NGINX_CONFIGURATION", encoding="utf-8")
            link = root / "link.conf"
            link.symlink_to(original)
            large = root / "oversized.conf"
            large.write_bytes(b"A" * 65537)
            fifo = root / "pipe.conf"
            if hasattr(os, "mkfifo"):
                os.mkfifo(fifo)
            cases = [(("--candidate-file", str(link)), "symlink"),
                     (("--candidate-file", str(large)), "oversized"),
                     (("--candidate-file", str(root)), "directory"),
                     (("--candidate-file", str(root / "missing")), "absent"),
                     (("--candidate-file", str(fifo)), "fifo"),
                     (("--wrong-file", str(original)), "bad-option"),
                     (("--candidate-file",), "missing-arg"),
                     (("--candidate-file", str(original), "--extra"), "extra-arg")]
            for arguments, label in cases:
                with self.subTest(label=label):
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        result = check.main(arguments)
                    receipt = json.loads(out.getvalue())
                    self.assertEqual(result, 2)
                    self.assertEqual(receipt["verdict"], "HOLD")
                    self.assertTrue(all(receipt[k] is False for k in check.FALSE_FLAGS))
                    self.assertNotIn("fictional_secret", out.getvalue())
                    self.assertNotIn("THIS_IS_NOT_A_REAL", out.getvalue())

    def test_actual_lightup_wsgi_role_and_csrf_survive_real_nginx(self):
        # This WSGI test uses the actual LightUp web app and a disposable
        # tenant SQLite DB; it never opens an external listener or emits a
        # real customer authorization grant.
        if not shutil.which("nginx"):
            self.skipTest("nginx missing: cannot prove integrated WSGI security")
        with tempfile.TemporaryDirectory(prefix="lightup-scope-real-app-") as tmp:
            store = DomainStore(Path(tmp) / "app.sqlite3")
            op_user = store.bootstrap_operator(
                "synthetic-op@lab.invalid", "Operator", "synthetic-password"
            )
            operator = store.context_for_user(op_user.user_id)
            client = store.create_client(operator, "Synthetic Alpha")
            client_user = store.create_user(
                operator, "synthetic-client@lab.invalid", "Client",
                Role.CLIENT_ADMIN, client.client_id
            )
            op_token, op_csrf = store.create_session(op_user.user_id)
            client_token, client_csrf = store.create_session(client_user.user_id)
            app = create_app(store)
            template = self.template.replace(
                "        proxy_request_buffering on;",
                "".join(f'        proxy_set_header {name} "";\n'
                        for name in check.OVERRIDE_NAMES)
                + "        proxy_request_buffering on;",
            )

            def send(port, method, path, *, token=None, form=None, headers=None):
                request_headers = {"Host": "localhost"}
                if token:
                    request_headers["Cookie"] = "lightup_session=" + token
                data = None
                if form is not None:
                    data = urlencode(form).encode("ascii")
                    request_headers["Content-Type"] = (
                        "application/x-www-form-urlencoded"
                    )
                    request_headers["Origin"] = "http://localhost"
                request_headers.update(headers or {})
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request(method, path, body=data, headers=request_headers)
                    response = conn.getresponse()
                    return response.status, dict(response.getheaders()), response.read(32768)
                finally:
                    conn.close()

            def verify_real_app(port):
                baseline = len(store.list_clients(operator))
                request_baseline = len(store.list_assessment_requests(operator))
                portal = f"/portal/{client.client_id}/requests"
                for name in check.OVERRIDE_NAMES:
                    spoof = {name: "POST"}
                    code, _, body = send(
                        port, "GET", "/", token=op_token, headers=spoof
                    )
                    if code != 200 or b"Active testing" not in body:
                        return False
                    code, h, body = send(
                        port, "GET", "/", headers=spoof
                    )
                    if code != 303 or h.get("Location") != "/login":
                        return False
                    code, _, _ = send(
                        port, "GET", "/", token=client_token, headers=spoof
                    )
                    if code != 403:
                        return False
                    code, _, _ = send(
                        port, "POST", "/clients", token=op_token,
                        form={"name": "Never Created", "csrf": "forged"},
                        headers={name: "GET"}
                    )
                    if code != 403 or len(store.list_clients(operator)) != baseline:
                        return False
                    # A real client session with its own valid CSRF does not
                    # gain operator write access from a spoofed GET.
                    code, _, _ = send(
                        port, "POST", "/clients", token=client_token,
                        form={"name": "Cross Tenant", "csrf": client_csrf},
                        headers={name: "GET"}
                    )
                    if code != 403 or len(store.list_clients(operator)) != baseline:
                        return False
                    # A header must not turn an unauthenticated logout into
                    # a CSRF-free GET or revoke the existing operator session.
                    code, _, _ = send(
                        port, "POST", "/logout", token=op_token,
                        form={"csrf": "forged"}, headers={name: "GET"},
                    )
                    if code != 403 or store.session_context(op_token) is None:
                        return False
                    # A GET with an override to POST must not create an
                    # assessment request. This is a real client portal route,
                    # not an artificial unmatched URL.
                    code, _, _ = send(
                        port, "GET", portal, token=client_token,
                        headers={name: "POST"},
                    )
                    if code != 404 or len(store.list_assessment_requests(operator)) != request_baseline:
                        return False
                    # A client POST with a forged CSRF must not submit an
                    # assessment request even with a method downgrade header.
                    code, _, _ = send(
                        port, "POST", portal, token=client_token,
                        form={"assets": "synthetic.invalid", "risk": "1",
                              "csrf": "forged"},
                        headers={name: "GET"},
                    )
                    if code != 403 or len(store.list_assessment_requests(operator)) != request_baseline:
                        return False
                # Positive client-portal control: a valid same-session CSRF
                # must still reach the actual POST route despite GET spoofing.
                code, _, _ = send(
                    port, "POST", portal, token=client_token,
                    form={"assets": "synthetic.invalid", "risk": "1",
                          "csrf": client_csrf},
                    headers={check.OVERRIDE_NAMES[0]: "GET"},
                )
                if code != 303 or len(store.list_assessment_requests(operator)) != request_baseline + 1:
                    return False
                # A *legitimate* operator POST is still a POST even with
                # forged GET metadata, and needs the actual session CSRF.
                code, _, _ = send(
                    port, "POST", "/clients", token=op_token,
                    form={"name": "Synthetic Valid", "csrf": op_csrf},
                    headers={check.OVERRIDE_NAMES[0]: "GET"},
                )
                if code != 303 or len(store.list_clients(operator)) != baseline + 1:
                    return False
                # Valid logout is not disabled by a forged GET header: the
                # POST+CSRF must still revoke precisely this operator token.
                code, _, _ = send(
                    port, "POST", "/logout", token=op_token,
                    form={"csrf": op_csrf},
                    headers={check.OVERRIDE_NAMES[0]: "GET"},
                )
                if code != 303 or store.session_context(op_token) is not None:
                    return False
                code, h, _ = send(port, "GET", "/", token=op_token)
                return code == 303 and h.get("Location") == "/login"
            # The same real app must expose the deliberate upstream method
            # substitution through a failed CSRF/write-negative control.
            self.assertFalse(check.run_probe(
                template, force_rewrite=True, wsgi_app=app,
                oracle=verify_real_app
            ))
            self.assertTrue(check.run_probe(
                template, wsgi_app=app, oracle=verify_real_app
            ))

    def test_disposable_fixture_detects_deliberate_method_rewrite(self):
        if not shutil.which("nginx"):
            self.skipTest("real nginx unavailable; loopback e2e not proved here")
        # Only for the standalone lab witness: grant the candidate the four
        # stripping directives that PR #1155 has not integrated into main.
        stripped = self.template.replace(
            "        proxy_request_buffering on;",
            "".join(f"        proxy_set_header {name} \"\";\n"
                    for name in check.OVERRIDE_NAMES)
            + "        proxy_request_buffering on;",
        )
        self.assertTrue(check.run_probe(stripped))
        # A deliberately vulnerable proxy_method rewrite MUST be caught.
        self.assertFalse(check.run_probe(stripped, force_rewrite=True))

    def test_single_missing_stripping_rule_is_detected_by_real_nginx(self):
        if not shutil.which("nginx"):
            self.skipTest("nginx unavailable; cannot prove a real header omission")
        # Start with the fully protected candidate, then remove each one of
        # the four independent directives. The network probe, not an
        # inspection of text alone, must catch every missing strip.
        stripped = self.template.replace(
            "        proxy_request_buffering on;",
            "".join(f'        proxy_set_header {name} "";\n'
                    for name in check.OVERRIDE_NAMES)
            + "        proxy_request_buffering on;",
        )
        self.assertTrue(check.run_probe(stripped))
        for name in check.OVERRIDE_NAMES:
            with self.subTest(header=name):
                altered = stripped.replace(
                    f'        proxy_set_header {name} "";\n', ""
                )
                self.assertFalse(check.run_probe(altered))

    def test_current_shipped_template_does_not_silently_claim_e2e_pass(self):
        if not shutil.which("nginx"):
            self.skipTest("real nginx unavailable; current template unproven")
        # Integration gap remains explicit while #1155 has not landed.
        actual = check.run_probe(self.template)
        if not all(f"proxy_set_header {name} \"\";" in self.template
                   for name in check.OVERRIDE_NAMES):
            self.assertFalse(actual, "unstripped headers must not pass")
        # If a later source owner installs stripping correctly, this assertion
        # still requires a real Nginx run rather than a static-only green.
        else:
            self.assertTrue(actual)


if __name__ == "__main__":
    unittest.main()
