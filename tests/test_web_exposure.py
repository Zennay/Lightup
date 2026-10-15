from __future__ import annotations

import contextlib
import threading
import unittest
from http.server import ThreadingHTTPServer

from lightup.labeval import LabIsolationError
from lightup.labfixtures import PROFILES, make_handler
from lightup.workers import web_exposure as we
from lightup.workers.web_exposure import Response


def R(status=200, headers=(), body=""):
    return Response(status, tuple(headers), body)


@contextlib.contextmanager
def serve(profile):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(profile))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()


class EvaluatorTests(unittest.TestCase):
    def test_cookie_flags(self):
        self.assertEqual(we.evaluate_cookies(R(headers=[("Set-Cookie", "a=1; Path=/")])),
                         {"cookie-missing-httponly", "cookie-missing-samesite"})
        self.assertEqual(we.evaluate_cookies(
            R(headers=[("set-cookie", "a=1; HttpOnly; SameSite=Lax")])), set())
        self.assertEqual(we.evaluate_cookies(R()), set())

    def test_cors(self):
        self.assertEqual(we.evaluate_cors(R(headers=[("Access-Control-Allow-Origin", we.PROBE_ORIGIN)])),
                         {"cors-reflected-origin"})
        self.assertEqual(we.evaluate_cors(R(headers=[("Access-Control-Allow-Origin", "*")])),
                         {"cors-wildcard-origin"})
        self.assertEqual(we.evaluate_cors(
            R(headers=[("Access-Control-Allow-Origin", "https://app.example")])), set())

    def test_exposed_files_need_signature_not_just_200(self):
        self.assertEqual(we.evaluate_git(R(body="ref: refs/heads/main")), {"exposed-git-metadata"})
        self.assertEqual(we.evaluate_git(R(body="<html>SPA fallback</html>")), set())
        self.assertEqual(we.evaluate_git(R(404, body="ref: x")), set())
        self.assertEqual(we.evaluate_env(R(body="A_KEY=1\nB_KEY=2")), {"exposed-env-file"})
        self.assertEqual(we.evaluate_env(R(body="<html>catch-all</html>")), set())
        self.assertEqual(we.evaluate_env(R(body="ONE=1")), set())

    def test_listing_methods_reflection_redirect_error(self):
        self.assertEqual(we.evaluate_listing(R(body="<title>Index of /static/</title>")),
                         {"directory-listing-enabled"})
        self.assertEqual(we.evaluate_listing(R(body="<p>files</p>")), set())
        self.assertEqual(we.evaluate_methods(R(204, [("Allow", "GET, TRACE")])),
                         {"risky-http-methods-enabled"})
        self.assertEqual(we.evaluate_methods(R(204, [("Allow", "GET, POST")])), set())
        self.assertEqual(we.evaluate_reflection(R(body="x <luabc> y"), "luabc"),
                         {"reflected-input-unencoded"})
        self.assertEqual(we.evaluate_reflection(R(body="x &lt;luabc&gt; y"), "luabc"), set())
        self.assertEqual(we.evaluate_redirect(R(302, [("Location", we.REDIRECT_PROBE)])),
                         {"open-redirect-candidate"})
        self.assertEqual(we.evaluate_redirect(R(302, [("Location", "/home")])), set())
        self.assertEqual(we.evaluate_redirect(R(200, [("Location", we.REDIRECT_PROBE)])), set())
        self.assertEqual(we.evaluate_error(R(500, body="Traceback (most recent call last):")),
                         {"verbose-error-disclosure"})
        self.assertEqual(we.evaluate_error(R(404, body="not found")), set())

    def test_catalog_is_complete(self):
        for check_id, (title, severity, impact, fix) in we.WEB_EXPOSURE_CHECKS.items():
            self.assertTrue(title and impact and fix, check_id)


class LabBoundaryTests(unittest.TestCase):
    def test_refuses_public_and_https_targets(self):
        for url in ("http://8.8.8.8/", "http://example.com/", "https://127.0.0.1/"):
            with self.assertRaises(LabIsolationError, msg=url):
                we.observe(url)

    def test_handler_refuses_non_lab_context(self):
        class Ctx:
            is_lab = False
        with self.assertRaises(LabIsolationError):
            we.run_web_exposure(Ctx(), {"url": "http://127.0.0.1:9/"})


class LiveFixtureTests(unittest.TestCase):
    def test_planted_truth_matches_exactly_and_hardened_is_clean(self):
        for name, profile in PROFILES.items():
            with self.subTest(profile=name), serve(profile) as url:
                self.assertEqual(set(we.observe(url).issues), set(profile.app_weaknesses))

    def test_each_planted_weakness_detected_in_isolation(self):
        from dataclasses import replace
        base = PROFILES["hardened"]
        for check_id in sorted(we.WEB_EXPOSURE_CHECKS):
            profile = replace(base, profile_id=f"only-{check_id}",
                              app_weaknesses=frozenset({check_id}),
                              expected_check_ids=(check_id,))
            with self.subTest(check=check_id), serve(profile) as url:
                self.assertEqual(set(we.observe(url).issues), {check_id})


if __name__ == "__main__":
    unittest.main()
