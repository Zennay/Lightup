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
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.security import WebSecurity

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
            for candidate, get_mutant, post_mutant, expected, exit_code in (
                (True, False, False, "REVIEW_ONLY", 3),
                (True, True, False, "HOLD", 2),
                (True, False, True, "HOLD", 2),
                (False, False, False, "HOLD", 2),
            ):
                with self.subTest(candidate=candidate,
                                  get_mutant=get_mutant,
                                  post_mutant=post_mutant), \
                     patch.object(check, "run_probe",
                                  side_effect=[candidate, get_mutant, post_mutant]) as probe:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = check.main()
                receipt = json.loads(out.getvalue())
                self.assertEqual(code, exit_code)
                self.assertEqual(receipt["verdict"], expected)
                self.assertTrue(all(receipt[k] is False for k in check.FALSE_FLAGS))
                self.assertEqual(
                    probe.call_count,
                    1 if not candidate else (2 if get_mutant else 3),
                )

    def test_malformed_upstream_receipts_always_fail_closed(self):
        good = {
            "method": "POST", "path": "/__scope_method_fixture__",
            "body": "x", "nonce": "synthetic-nonce-001",
            "override_headers": {},
        }
        self.assertTrue(check._receipt_is_exact(good, "POST", "synthetic-nonce-001"))
        bad = [None, False, 1, [], (), "", "APPROVED",
               {**good, "method": True},
               {**good, "path": True},
               {**good, "body": True},
               {**good, "override_headers": []},
               {**good, "override_headers": {"X-Method-Override": "GET"}},
               {**good, "nonce": True},
               {**good, "nonce": "stale-replayed-nonce"},
               {**good, "authorizes_targets": True},
               {key: val for key, val in good.items() if key != "body"}]
        for receipt in bad:
            with self.subTest(receipt=repr(receipt)):
                self.assertFalse(check._receipt_is_exact(receipt, "POST", "synthetic-nonce-001"))
        self.assertFalse(check._receipt_is_exact(good, "GET", "synthetic-nonce-001"))
        self.assertFalse(check._receipt_is_exact(good, "POST", "fresh-nonce-002"))

    def test_synthetic_upstream_http_framing_is_exact_and_bounded(self):
        message = json.dumps({
            "method": "POST", "path": "/__scope_method_fixture__",
            "body": "x", "nonce": "synthetic-nonce-001",
            "override_headers": {},
        }, sort_keys=True).encode("ascii")
        ordinary = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(message))),
        ]
        valid = Mock()
        valid.status = 200
        valid.getheaders.return_value = ordinary
        valid.read.return_value = message
        self.assertTrue(check._receipt_is_exact(
            check._decode_lab_response(valid), "POST", "synthetic-nonce-001",
        ))
        valid.read.assert_called_once_with(len(message) + 1)
        # Mixed case is valid HTTP; case-sensitive header parsing is not.
        valid.getheaders.return_value = [
            ("content-type", "application/json"),
            ("CONTENT-length", str(len(message))),
        ]
        self.assertTrue(check._receipt_is_exact(
            check._decode_lab_response(valid), "POST", "synthetic-nonce-001",
        ))
        # Even if a valid JSON prefix fits in the first 4 KiB, the witness
        # must reject any unexplained trailing bytes or missing HTTP bytes.
        cases = [
            ("missing_length", [ordinary[0]], message),
            ("duplicate_length", ordinary + [ordinary[1]], message),
            ("conflicting_length", ordinary + [("CONTENT-LENGTH", "1")], message),
            ("chunked_conflict", ordinary + [("Transfer-Encoding", "chunked")], message),
            ("wrong_type", [("Content-Type", "text/plain"), ordinary[1]], message),
            ("duplicate_type", ordinary + [ordinary[0]], message),
            ("leading_zero_length", [ordinary[0], ("Content-Length", "0" + str(len(message)))], message),
            ("whitespace_length", [ordinary[0], ("Content-Length", " " + str(len(message)))], message),
            ("too_large", [ordinary[0], ("Content-Length", "4097")], message),
            ("empty", [ordinary[0], ("Content-Length", "0")], message),
            ("short_body", ordinary, message[:-1]),
            ("extra_body", ordinary, message + b"EXTRA"),
            ("bad_header_type", [("Content-Type", b"application/json"), ordinary[1]], message),
        ]
        for label, headers, payload in cases:
            with self.subTest(label=label):
                fake = Mock()
                fake.status = 200
                fake.getheaders.return_value = headers
                fake.read.return_value = payload
                with self.assertRaises((RuntimeError, ValueError)):
                    check._decode_lab_response(fake)
        for bad_status in (204, 301, 400, 500):
            with self.subTest(http_status=bad_status):
                fake = Mock()
                fake.status = bad_status
                fake.getheaders.return_value = ordinary
                fake.read.return_value = message
                with self.assertRaises(RuntimeError):
                    check._decode_lab_response(fake)

    def test_upstream_json_parser_rejects_duplicate_and_nonfinite_evidence(self):
        # A duplicate nonce/method with last-wins JSON semantics would make a
        # replay or rewritten upstream's evidence misleading. Parse all object
        # depths without silently normalizing duplicates.
        encoded_alias = b'{"method":"POST","' + b"\\\\u006dethod" + b'":"GET"}'
        malformed = (
            b'{"method":"POST","method":"GET"}',
            encoded_alias,
            b'{"outer":{"nonce":"new","nonce":"replayed"}}',
            b'{"nonce":NaN}',
            b'{"nonce":Infinity}',
            b'{"nonce":-Infinity}',
        )
        for payload in malformed:
            with self.subTest(payload=payload[:36]):
                result = Mock()
                result.status = 200
                result.getheaders.return_value = [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(payload))),
                ]
                result.read.return_value = payload
                with self.assertRaises(ValueError):
                    check._decode_lab_response(result)
        # Valid ordinary JSON still passes through decoding, before the
        # independent method/path/body/nonce/headers trust-boundary checker.
        clean = b'{"nonce":"synthetic-fresh"}'
        result = Mock()
        result.status = 200
        result.getheaders.return_value = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(clean))),
        ]
        result.read.return_value = clean
        self.assertEqual(check._decode_lab_response(result),
                         {"nonce": "synthetic-fresh"})

    def test_requests_issue_distinct_challenges_and_reject_replayed_receipts(self):
        # A stale but otherwise byte-perfect response must not stand in for a
        # fresh Nginx/WSGI roundtrip. Use only a disposable synthetic echo.
        if not shutil.which("nginx"):
            self.skipTest("real Nginx unavailable; nonce replay not probed")
        protected = self.template.replace(
            "        proxy_request_buffering on;",
            "".join(f'        proxy_set_header {name} "";\n'
                    for name in check.OVERRIDE_NAMES)
            + "        proxy_request_buffering on;",
        )
        real_request = check._request
        observed = []
        def witness(port, method, headers):
            receipt, nonce = real_request(port, method, headers)
            observed.append(nonce)
            self.assertTrue(check._receipt_is_exact(receipt, method, nonce))
            self.assertFalse(check._receipt_is_exact(receipt, method, nonce + "-replay"))
            return receipt, nonce
        with patch.object(check, "_request", side_effect=witness):
            self.assertTrue(check.run_probe(protected))
        self.assertEqual(len(observed), 42)
        self.assertEqual(len(observed), len(set(observed)))
        self.assertTrue(all(len(nonce) == 32 for nonce in observed))

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
            other_client = store.create_client(operator, "Synthetic Beta")
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

            def send_raw_double_method_header(port, name, method):
                # Dict-based APIs flatten duplicate field names. Exercise
                # actual HTTP/1.1 on the proxy for opposite-casing values.
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                body = (
                    urlencode({"name": "Duplicate Must Not Write",
                               "csrf": "forged"}).encode("ascii")
                    if method == "POST" else b""
                )
                try:
                    conn.putrequest(method, "/clients" if method == "POST" else "/",
                                    skip_host=True)
                    conn.putheader("Host", "localhost")
                    conn.putheader("Cookie", "lightup_session=" + op_token)
                    conn.putheader(name, "GET" if method == "POST" else "DELETE")
                    conn.putheader(name.lower(), "POST" if method == "POST" else "POST")
                    if method == "POST":
                        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
                        conn.putheader("Origin", "http://localhost")
                        conn.putheader("Content-Length", str(len(body)))
                    conn.endheaders(body or None)
                    response = conn.getresponse()
                    status = response.status
                    response.read(8192)
                    return status
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
                    # The Nginx→actual webapp role/CSRF boundary must also
                    # survive *two* raw wire headers differing only by case,
                    # not just flattened Python dictionaries.
                    if send_raw_double_method_header(port, name, "GET") != 200:
                        return False
                    if send_raw_double_method_header(port, name, "POST") != 403:
                        return False
                    if len(store.list_clients(operator)) != baseline:
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
                    # The client's valid own CSRF must not allow a request in
                    # another tenant just because a header demands GET.
                    wrong_tenant = f"/portal/{other_client.client_id}/requests"
                    code, _, _ = send(
                        port, "POST", wrong_tenant, token=client_token,
                        form={"assets": "synthetic.invalid", "risk": "1",
                              "csrf": client_csrf},
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
            self.assertFalse(check.run_probe(
                template, force_rewrite_post=True, wsgi_app=app,
                oracle=verify_real_app
            ))
            self.assertTrue(check.run_probe(
                template, wsgi_app=app, oracle=verify_real_app
            ))

    def test_real_app_production_security_mode_keeps_canonical_method(self):
        # Simulate the deployed HTTPS-terminating proxy semantics locally,
        # without TLS certificates, customer hosts, or installed services.
        # Unlike the dev-mode app fixture, this invokes real WebSecurity's
        # production host/proxy-peer/protocol checks before any route.
        if not shutil.which("nginx"):
            self.skipTest("no disposable Nginx; production-mode WSGI unproven")
        with tempfile.TemporaryDirectory(prefix="lightup-scope-prodshape-") as folder:
            store = DomainStore(Path(folder) / "isolated.sqlite3")
            user = store.bootstrap_operator(
                "prodshape@lab.invalid", "Synthetic", "fictional-password"
            )
            operator = store.context_for_user(user.user_id)
            token, csrf = store.create_session(user.user_id)
            app = create_app(
                store,
                security=WebSecurity(public_origin="https://lightup.example.com"),
            )
            template = self.template.replace(
                "        proxy_request_buffering on;",
                "".join(f'        proxy_set_header {name} "";\n'
                        for name in check.OVERRIDE_NAMES)
                + "        proxy_request_buffering on;",
            )

            def send(port, method, path, spoof, *, form=None):
                headers = {
                    "Host": "lightup.example.com",
                    "Cookie": "lightup_session=" + token,
                }
                payload = None
                if form is not None:
                    payload = urlencode(form).encode("ascii")
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    headers["Origin"] = "https://lightup.example.com"
                headers.update(spoof)
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request(method, path, body=payload, headers=headers)
                    result = conn.getresponse()
                    return result.status, dict(result.getheaders()), result.read(8192)
                finally:
                    conn.close()

            def proof(port):
                baseline = len(store.list_clients(operator))
                for name in check.OVERRIDE_NAMES:
                    status, headers, _ = send(
                        port, "GET", "/", {name: "POST"},
                    )
                    if status != 200 or headers.get("Strict-Transport-Security") != "max-age=31536000":
                        return False
                    # A malicious "downgrade" to GET must not bypass CSRF
                    # despite a real HTTPS-production-mode origin/proxy check.
                    status, headers, _ = send(
                        port, "POST", "/clients", {name: "GET"},
                        form={"name": "Must Never Exist", "csrf": "invalid"},
                    )
                    if status != 403 or len(store.list_clients(operator)) != baseline:
                        return False
                    # A real, otherwise-correct CSRF must not defeat the
                    # production Origin and Fetch Metadata gates if a client
                    # spoofs the HTTP method to a "safe" GET.
                    for adversarial in (
                        {"Origin": "https://attacker.invalid"},
                        {"Sec-Fetch-Site": "cross-site"},
                    ):
                        status, _, _ = send(
                            port, "POST", "/clients",
                            {name: "GET", **adversarial},
                            form={"name": "Cross Origin Forbidden", "csrf": csrf},
                        )
                        if status != 403 or len(store.list_clients(operator)) != baseline:
                            return False
                status, headers, _ = send(
                    port, "POST", "/clients",
                    {check.OVERRIDE_NAMES[0]: "GET"},
                    form={"name": "Prodshape Synthetic", "csrf": csrf},
                )
                return status == 303 and len(store.list_clients(operator)) == baseline + 1

            self.assertFalse(check.run_probe(
                template, force_rewrite=True, wsgi_app=app, oracle=proof
            ))
            self.assertFalse(check.run_probe(
                template, force_rewrite_post=True, wsgi_app=app, oracle=proof
            ))
            self.assertTrue(check.run_probe(
                template, wsgi_app=app, oracle=proof
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
        # A GET incorrectly promoted into POST is independently detected.
        self.assertFalse(check.run_probe(stripped, force_rewrite_post=True))

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
