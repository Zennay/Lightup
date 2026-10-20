"""Lab-only web exposure worker: signatures, fail-closed gating, no content retention."""
import dataclasses
import os
import sys
import threading
import unittest
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.ai.orchestration import RunContext
from lightup.labeval import LabIsolationError
from lightup.labfixtures import PLANTED_FILES, PROFILES, make_handler
from lightup.workers import web_exposure


@contextmanager
def _serve(profile):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(profile))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()


class EvaluatorTests(unittest.TestCase):
    def test_cookie_flags(self):
        issues, names = web_exposure.evaluate_cookies(
            ["sid=1; Path=/", "pref=x; Secure; HttpOnly; SameSite=Lax"])
        self.assertEqual(names, ("sid", "pref"))
        self.assertEqual(set(issues), {"cookie-missing-secure", "cookie-missing-httponly",
                                       "cookie-missing-samesite"})
        self.assertEqual(web_exposure.evaluate_cookies(
            ["sid=1; Secure; HttpOnly; SameSite=Strict"])[0], ())

    def test_cors(self):
        origin = web_exposure.PROBE_ORIGIN
        self.assertIsNone(web_exposure.evaluate_cors({}))
        self.assertIsNone(web_exposure.evaluate_cors(
            {"access-control-allow-origin": "https://app.example"}))
        self.assertEqual(web_exposure.evaluate_cors(
            {"access-control-allow-origin": origin}), "cors-arbitrary-origin")
        self.assertEqual(web_exposure.evaluate_cors(
            {"access-control-allow-origin": origin,
             "access-control-allow-credentials": "true"}),
            "cors-credentialed-arbitrary-origin")

    def test_signatures_reject_soft_404_bodies(self):
        generic = b'{"service": "lightup-lab-fixture"}'
        for _path, _check, _sig, predicate in web_exposure.PATH_PROBES:
            self.assertFalse(predicate(generic))
            self.assertFalse(predicate(b"<html>Not found</html>"))


class LiveFixtureTests(unittest.TestCase):
    def test_leaky_profile_detected_without_retaining_contents(self):
        with _serve(PROFILES["leaky-webapp"]) as url:
            observation = web_exposure.observe(url)
        self.assertEqual(set(observation.issues),
                         set(PROFILES["leaky-webapp"].expected_check_ids))
        evidence = observation.to_json()
        for _content_type, body in PLANTED_FILES.values():
            for line in body.splitlines():
                self.assertNotIn(line.decode(), evidence)
        self.assertIn("session", observation.cookie_names)

    def test_hardened_profile_is_clean(self):
        with _serve(PROFILES["hardened"]) as url:
            self.assertEqual(web_exposure.observe(url).issues, ())


class GatingTests(unittest.TestCase):
    def test_public_and_https_targets_refused_before_connecting(self):
        for url in ("http://8.8.8.8/", "http://example.com/", "https://127.0.0.1/"):
            with self.subTest(url=url), self.assertRaises((LabIsolationError, PermissionError)):
                web_exposure.observe(url)

    def test_handler_refuses_non_lab_context(self):
        context = dataclasses.replace(RunContext.for_lab("r"), is_lab=False)
        with self.assertRaises(LabIsolationError):
            web_exposure.run_web_exposure(context, {"url": "http://127.0.0.1:1/"})


if __name__ == "__main__":
    unittest.main()
