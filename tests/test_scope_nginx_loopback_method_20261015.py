"""Synthetic, opt-in #1154 ingress proof; no production configuration changes."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = (Path(__file__).resolve().parents[1] / "scripts"
          / "scope_nginx_loopback_method_acceptance_20261015.py")
spec = importlib.util.spec_from_file_location("scope_1154_loopback", SOURCE)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ScopeIngressMethodE2ETest(unittest.TestCase):
    def setUp(self):
        self.template = check.TEMPLATE.read_text(encoding="utf-8")

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

    def test_candidate_file_cli_is_read_only_and_non_authorizing(self):
        if not shutil.which("nginx"):
            self.skipTest("real nginx needed for a candidate-file receipt")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "synthetic-nginx.conf"
            fixed = self.template.replace(
                "        proxy_request_buffering on;",
                "".join(f'        proxy_set_header {name} "";\\n'
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
                f'        proxy_set_header {check.OVERRIDE_NAMES[0]} "";\\n', ""
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
