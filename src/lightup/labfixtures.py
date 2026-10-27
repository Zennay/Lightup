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

from .labeval import ExpectedFinding
from .workers import web_exposure
from .workers.http_baseline import BASELINE_CHECKS, CAPABILITY_ID

# check_id -> (title, severity, capability_id)
_KNOWN_CHECKS = {check_id: (title, severity, CAPABILITY_ID)
                 for check_id, _header, title, severity, _impact, _remediation
                 in BASELINE_CHECKS}
_KNOWN_CHECKS.update({
    check_id: (title, severity, web_exposure.CAPABILITY_ID)
    for check_id, (title, severity, _impact, _remediation)
    in web_exposure.EXPOSURE_CHECKS.items()
})

# Planted file bodies. They are synthetic and contain no real credentials.
PLANTED_FILES: dict[str, tuple[str, bytes]] = {
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.env": ("text/plain",
              b"APP_ENV=lab\nDATABASE_URL=postgres://lab:lab@127.0.0.1/lab\n"
              b"SECRET_KEY=lab-fixture-not-a-secret\n"),
    "/backup.sql": ("application/sql",
                    b"CREATE TABLE users (id int, email text);\n"
                    b"INSERT INTO users VALUES (1, 'lab@example.test');\n"),
}
DIRECTORY_LISTING = (b"<html><head><title>Index of /</title></head><body>"
                     b"<a href=\"backup.sql\">backup.sql</a></body></html>")


@dataclass(frozen=True)
class FixtureProfile:
    """One planted-weakness configuration for the lab HTTP fixture."""

    profile_id: str
    description: str
    headers: tuple[tuple[str, str], ...]
    server_banner: str | None  # None -> the Server banner is suppressed
    expected_check_ids: tuple[str, ...]
    planted_files: tuple[str, ...] = ()  # keys of PLANTED_FILES served with 200
    directory_listing: bool = False      # "/" renders an autoindex page
    cors: str | None = None              # None | "reflect" | "reflect-credentials"
    cookies: tuple[str, ...] = ()        # Set-Cookie header values on "/"

    def __post_init__(self) -> None:
        unknown = [c for c in self.expected_check_ids if c not in _KNOWN_CHECKS]
        if unknown:
            raise ValueError(f"profile {self.profile_id!r} plants unknown checks: {unknown}")
        if len(set(self.expected_check_ids)) != len(self.expected_check_ids):
            raise ValueError(f"profile {self.profile_id!r} lists duplicate checks")
        unknown_files = [p for p in self.planted_files if p not in PLANTED_FILES]
        if unknown_files:
            raise ValueError(f"profile {self.profile_id!r} plants unknown files: {unknown_files}")
        if self.cors not in {None, "reflect", "reflect-credentials"}:
            raise ValueError(f"profile {self.profile_id!r} has unknown cors mode {self.cors!r}")


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
            profile_id="leaky-webapp",
            description="Hardened headers, but the deployment leaks: .git and "
                        ".env are readable, a SQL dump is downloadable, "
                        "directory listing is on, CORS reflects any origin "
                        "with credentials and the session cookie has no flags.",
            headers=(
                ("Content-Security-Policy", "default-src 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
            ),
            server_banner=None,
            expected_check_ids=(
                "exposed-git-metadata",
                "exposed-env-file",
                "exposed-database-dump",
                "directory-listing-enabled",
                "cors-credentialed-arbitrary-origin",
                "cookie-missing-secure",
                "cookie-missing-httponly",
                "cookie-missing-samesite",
            ),
            planted_files=("/.git/HEAD", "/.env", "/backup.sql"),
            directory_listing=True,
            cors="reflect-credentials",
            cookies=("session=lab-session-id; Path=/",),
        ),
    )
}


def expected_findings(profile: FixtureProfile) -> tuple[ExpectedFinding, ...]:
    """The profile's planted ground truth as scorable expected findings."""
    return tuple(
        ExpectedFinding(check_id, _KNOWN_CHECKS[check_id][0], _KNOWN_CHECKS[check_id][2],
                        _KNOWN_CHECKS[check_id][1].value)
        for check_id in profile.expected_check_ids
    )


def make_handler(profile: FixtureProfile) -> type[BaseHTTPRequestHandler]:
    """An HTTP handler class serving exactly the profile's headers."""

    class ProfileHandler(BaseHTTPRequestHandler):
        def version_string(self) -> str:  # controls the Server banner
            return profile.server_banner or ""

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            content_type = "application/json"
            body = json.dumps({"service": "lightup-lab-fixture",
                               "profile": profile.profile_id}).encode("utf-8")
            if path in profile.planted_files:
                content_type, body = PLANTED_FILES[path]
            elif path == "/" and profile.directory_listing:
                content_type, body = "text/html", DIRECTORY_LISTING
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in profile.headers:
                self.send_header(name, value)
            origin = self.headers.get("Origin")
            if profile.cors and origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                if profile.cors == "reflect-credentials":
                    self.send_header("Access-Control-Allow-Credentials", "true")
            if path == "/":
                for cookie in profile.cookies:
                    self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    return ProfileHandler
