"""Path-serving lab fixtures with planted web-configuration weaknesses.

The baseline :mod:`lightup.labfixtures` profiles only vary response headers.
The web-exposure worker inspects *paths and bodies*, so it needs richer
fixtures: a loopback server that serves specific development/metadata paths,
reflects CORS, sets cookies and can behave as a catch-all ("soft-404") server.

As with the header fixtures, the planted ground truth (which
``WEB_EXPOSURE_CHECKS`` ids are expected to fire) is hand-maintained here and
never derived from running the engine, so a perfect benchmark score means the
engine found what was planted.

The fixture still binds loopback-only; the planted weaknesses are responses,
nothing executable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

from .labeval import ExpectedFinding
from .workers.web_exposure import CAPABILITY_ID, WEB_EXPOSURE_CHECKS


@dataclass(frozen=True)
class WebFixtureProfile:
    """One planted web-exposure configuration for a loopback fixture."""

    profile_id: str
    description: str
    # path -> (content_type, body). Served verbatim for GET.
    served_paths: dict[str, tuple[str, bytes]] = field(default_factory=dict)
    root_body: bytes = b'{"service":"lightup-web-fixture"}'
    root_content_type: str = "application/json"
    set_cookies: tuple[str, ...] = ()          # raw Set-Cookie header values
    reflect_cors_with_credentials: bool = False
    allow_header: str | None = None            # value for OPTIONS Allow
    catch_all: bool = False                    # 200 + root_body for every path
    error_body: bytes | None = None            # body for the malformed-query probe (>=500)
    expected_check_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        unknown = [c for c in self.expected_check_ids if c not in WEB_EXPOSURE_CHECKS]
        if unknown:
            raise ValueError(f"profile {self.profile_id!r} plants unknown checks: {unknown}")
        if len(set(self.expected_check_ids)) != len(self.expected_check_ids):
            raise ValueError(f"profile {self.profile_id!r} lists duplicate checks")


_GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x\n"
_DOTENV = b"DB_PASSWORD=lab-placeholder\nAPI_TOKEN=lab-placeholder\nSECRET_KEY=lab\n"
_TRACE = (b"Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 1\n"
          b"Exception Value: lab error\n")

WEB_PROFILES: dict[str, WebFixtureProfile] = {
    profile.profile_id: profile
    for profile in (
        WebFixtureProfile(
            profile_id="leaky-app",
            description="SCM metadata, a dotenv file, a diagnostics endpoint, "
                        "debug stack traces, a weak session cookie and "
                        "origin-reflecting CORS are all exposed.",
            served_paths={
                "/.git/config": ("text/plain", _GIT_CONFIG),
                "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
                "/.env": ("text/plain", _DOTENV),
                "/actuator/health": ("application/json", b'{"status":"UP"}'),
            },
            set_cookies=("sessionid=abc123; Path=/",),
            reflect_cors_with_credentials=True,
            allow_header="GET, POST, OPTIONS, TRACE",
            error_body=_TRACE,
            expected_check_ids=(
                "exposed-scm-metadata",
                "exposed-dotenv",
                "unauthenticated-diagnostics",
                "stack-trace-disclosure",
                "session-cookie-missing-httponly",
                "session-cookie-missing-samesite",
                "permissive-cors-reflection",
                "trace-method-enabled",
            ),
        ),
        WebFixtureProfile(
            profile_id="web-hardened",
            description="No dev paths served, hardened session cookie, strict "
                        "CORS and no TRACE: the planted ground truth is zero findings.",
            set_cookies=("sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict",),
            reflect_cors_with_credentials=False,
            allow_header="GET, POST, OPTIONS",
            expected_check_ids=(),
        ),
        WebFixtureProfile(
            profile_id="catch-all",
            description="A server that returns 200 with the same body for every "
                        "path. Soft-404 calibration must suppress all path checks.",
            catch_all=True,
            allow_header="GET, OPTIONS",
            expected_check_ids=(),
        ),
    )
}


def web_expected_findings(profile: WebFixtureProfile) -> tuple[ExpectedFinding, ...]:
    return tuple(
        ExpectedFinding(check_id, WEB_EXPOSURE_CHECKS[check_id][0], CAPABILITY_ID,
                        WEB_EXPOSURE_CHECKS[check_id][1].value)
        for check_id in profile.expected_check_ids
    )


def make_web_handler(profile: WebFixtureProfile) -> type[BaseHTTPRequestHandler]:
    class WebProfileHandler(BaseHTTPRequestHandler):
        def version_string(self) -> str:
            return "LightUpWebLab/0.1"

        def _send(self, status: int, content_type: str, body: bytes,
                  extra: list[tuple[str, str]] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (extra or []):
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _cors_header(self) -> list[tuple[str, str]]:
            origin = self.headers.get("Origin")
            if origin and profile.reflect_cors_with_credentials:
                return [("Access-Control-Allow-Origin", origin),
                        ("Access-Control-Allow-Credentials", "true")]
            return []

        def do_OPTIONS(self):
            extra = list(self._cors_header())
            if profile.allow_header:
                extra.append(("Allow", profile.allow_header))
            self._send(204, "text/plain", b"", extra)

        def do_GET(self):
            path = urlparse(self.path).path
            query = urlparse(self.path).query
            extra = list(self._cors_header())
            for cookie in profile.set_cookies:
                extra.append(("Set-Cookie", cookie))

            if profile.catch_all:
                self._send(200, profile.root_content_type, profile.root_body, extra)
                return

            if query and profile.error_body is not None and "lightup" in query:
                self._send(500, "text/html", profile.error_body, extra)
                return

            if path in profile.served_paths:
                content_type, body = profile.served_paths[path]
                self._send(200, content_type, body, extra)
                return

            if path in ("/", ""):
                self._send(200, profile.root_content_type, profile.root_body, extra)
                return

            self._send(404, "text/plain", b"not found", extra)

        def log_message(self, fmt, *args):
            return

    return WebProfileHandler
