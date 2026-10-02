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
from .workers.http_baseline import BASELINE_CHECKS, CAPABILITY_ID

_KNOWN_CHECKS = {check_id: (title, severity)
                 for check_id, _header, title, severity, _impact, _remediation
                 in BASELINE_CHECKS}


@dataclass(frozen=True)
class FixtureProfile:
    """One planted-weakness configuration for the lab HTTP fixture."""

    profile_id: str
    description: str
    headers: tuple[tuple[str, str], ...]
    server_banner: str | None  # None -> the Server banner is suppressed
    expected_check_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        unknown = [c for c in self.expected_check_ids if c not in _KNOWN_CHECKS]
        if unknown:
            raise ValueError(f"profile {self.profile_id!r} plants unknown checks: {unknown}")
        if len(set(self.expected_check_ids)) != len(self.expected_check_ids):
            raise ValueError(f"profile {self.profile_id!r} lists duplicate checks")


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
    """An HTTP handler class serving exactly the profile's headers."""

    class ProfileHandler(BaseHTTPRequestHandler):
        def version_string(self) -> str:  # controls the Server banner
            return profile.server_banner or ""

        def do_GET(self):
            body = json.dumps({"service": "lightup-lab-fixture",
                               "profile": profile.profile_id}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in profile.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    return ProfileHandler
