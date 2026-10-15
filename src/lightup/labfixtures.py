"""Lab fixture profiles: deliberately planted weaknesses with ground truth.

Serious benchmarks need fixtures where the *planted* issues are known
independently of the engine that scores them. A :class:`FixtureProfile`
describes exactly which defensive headers a loopback fixture sends and which
baseline checks are therefore expected to fire. The expected check ids are
hand-maintained ground truth — never derived from running the engine — so a
perfect score means the engine found what was planted, not that it agreed
with itself.

The profiles only configure *what the fixture serves*; the fixture itself
still binds to loopback only (see ``lab/vuln_fixture.py``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from .labeval import ExpectedFinding
from .workers.http_baseline import BASELINE_CHECKS, CAPABILITY_ID
from .workers.web_exposure import WEB_EXPOSURE_CHECKS

_KNOWN_CHECKS = {check_id: (title, severity)
                 for check_id, _header, title, severity, _impact, _remediation
                 in BASELINE_CHECKS}
_KNOWN_CHECKS.update({check_id: (title, severity)
                      for check_id, (title, severity, _i, _r) in WEB_EXPOSURE_CHECKS.items()})


@dataclass(frozen=True)
class FixtureProfile:
    """One planted-weakness configuration for the lab HTTP fixture."""

    profile_id: str
    description: str
    headers: tuple[tuple[str, str], ...]
    server_banner: str | None  # None -> the Server banner is suppressed
    expected_check_ids: tuple[str, ...]
    # Web-exposure weaknesses this profile plants (subset of WEB_EXPOSURE_CHECKS).
    app_weaknesses: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        unknown = [c for c in self.expected_check_ids if c not in _KNOWN_CHECKS]
        if unknown:
            raise ValueError(f"profile {self.profile_id!r} plants unknown checks: {unknown}")
        if not self.app_weaknesses <= set(WEB_EXPOSURE_CHECKS):
            raise ValueError(f"profile {self.profile_id!r} plants unknown app weaknesses")
        if not self.app_weaknesses <= set(self.expected_check_ids):
            raise ValueError(f"profile {self.profile_id!r} must list planted app weaknesses as expected")
        if len(set(self.expected_check_ids)) != len(self.expected_check_ids):
            raise ValueError(f"profile {self.profile_id!r} lists duplicate checks")


# cors-wildcard-origin is mutually exclusive with reflection on one endpoint.
WEB_EXPOSURE_CHECKS_PLANTED = frozenset(WEB_EXPOSURE_CHECKS) - {"cors-wildcard-origin"}

PROFILES: dict[str, FixtureProfile] = {
    profile.profile_id: profile
    for profile in (
        FixtureProfile(
            profile_id="exposed",
            description="No defensive headers and a verbose server banner: "
                        "every baseline check fires.",
            headers=(),
            server_banner="LightUpLab/0.1 Python/3",
            expected_check_ids=(
                "missing-content-security-policy",
                "missing-x-content-type-options",
                "missing-x-frame-options",
                "missing-referrer-policy",
                "server-banner-disclosure",
            ),
        ),
        FixtureProfile(
            profile_id="partially-hardened",
            description="CSP and nosniff are set; clickjacking protection and "
                        "referrer policy are still missing and the banner leaks.",
            headers=(
                ("Content-Security-Policy", "default-src 'none'"),
                ("X-Content-Type-Options", "nosniff"),
            ),
            server_banner="LightUpLab/0.1",
            expected_check_ids=(
                "missing-x-frame-options",
                "missing-referrer-policy",
                "server-banner-disclosure",
            ),
        ),
        FixtureProfile(
            profile_id="hardened",
            description="All baseline headers present and the banner stripped: "
                        "the planted ground truth is zero findings.",
            headers=(
                ("Content-Security-Policy", "default-src 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
            ),
            server_banner=None,
            expected_check_ids=(),
        ),
        FixtureProfile(
            profile_id="vulnerable-app",
            description="Hardened headers but a sloppy application: weak cookies, "
                        "reflective CORS, exposed .git/.env, listing, risky methods, "
                        "unencoded reflection, open redirect and verbose errors.",
            headers=(
                ("Content-Security-Policy", "default-src 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
            ),
            server_banner=None,
            expected_check_ids=tuple(sorted(WEB_EXPOSURE_CHECKS_PLANTED)),
            app_weaknesses=WEB_EXPOSURE_CHECKS_PLANTED,
        ),
    )
}


def expected_findings(profile: FixtureProfile) -> tuple[ExpectedFinding, ...]:
    """The profile's planted ground truth as scorable expected findings."""
    return tuple(
        ExpectedFinding(check_id, _KNOWN_CHECKS[check_id][0], CAPABILITY_ID,
                        _KNOWN_CHECKS[check_id][1].value)
        for check_id in profile.expected_check_ids
    )


def make_handler(profile: FixtureProfile) -> type[BaseHTTPRequestHandler]:
    """An HTTP handler class serving exactly the profile's headers and planted app weaknesses."""
    weak = profile.app_weaknesses

    class ProfileHandler(BaseHTTPRequestHandler):
        def version_string(self) -> str:  # controls the Server banner
            return profile.server_banner or ""

        def _send(self, status, body, content_type="text/html", extra=()):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for name, value in profile.headers:
                self.send_header(name, value)
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_OPTIONS(self):
            allow = "GET, HEAD, OPTIONS"
            if "risky-http-methods-enabled" in weak:
                allow += ", TRACE, PUT, DELETE"
            self._send(204, "", extra=(("Allow", allow),))

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            path = parsed.path
            if path == "/.git/HEAD" and "exposed-git-metadata" in weak:
                return self._send(200, "ref: refs/heads/main\n", "text/plain")
            if path == "/.env" and "exposed-env-file" in weak:
                return self._send(200, "DB_PASSWORD=lab-planted\nAPI_KEY=lab-planted\n", "text/plain")
            if path == "/static/" and "directory-listing-enabled" in weak:
                return self._send(200, "<html><title>Index of /static/</title><h1>Index of /static/</h1></html>")
            if "open-redirect-candidate" in weak and path == "/" and ("next" in query or "url" in query):
                target = (query.get("next") or query.get("url"))[0]
                return self._send(302, "", extra=(("Location", target),))
            if path == "/":
                extra = []
                if "cookie-missing-httponly" in weak or "cookie-missing-samesite" in weak:
                    cookie = "sid=lab-planted; Path=/"
                    if "cookie-missing-httponly" not in weak:
                        cookie += "; HttpOnly"
                    if "cookie-missing-samesite" not in weak:
                        cookie += "; SameSite=Lax"
                    extra.append(("Set-Cookie", cookie))
                origin = self.headers.get("Origin")
                if origin and "cors-reflected-origin" in weak:
                    extra.append(("Access-Control-Allow-Origin", origin))
                    extra.append(("Access-Control-Allow-Credentials", "true"))
                elif "cors-wildcard-origin" in weak:
                    extra.append(("Access-Control-Allow-Origin", "*"))
                if "reflected-input-unencoded" in weak and "lightup_probe" in query:
                    return self._send(200, f"<html>You searched: {query['lightup_probe'][0]}</html>",
                                      extra=extra)
                body = json.dumps({"service": "lightup-lab-fixture",
                                   "profile": profile.profile_id})
                return self._send(200, body, "application/json", extra)
            if "verbose-error-disclosure" in weak:
                return self._send(500, "Traceback (most recent call last):\n  File \"app.py\", line 1\n",
                                  "text/plain")
            return self._send(404, "not found", "text/plain")

        def log_message(self, fmt, *args):
            return

    return ProfileHandler
