"""Lab-only web exposure worker.

Goes beyond the header baseline: a fixed, small set of **non-destructive**
probes against one isolated lab web target, each judged by pure evaluator
functions that require positive evidence (a verifiable signature in the
response), never mere absence of a status code:

- cookie flags (``Set-Cookie`` without HttpOnly / SameSite);
- CORS policy (reflected arbitrary origin, wildcard, credentials);
- exposed ``/.git/HEAD`` and ``/.env`` (content signature required);
- directory listing on ``/static/``;
- risky HTTP methods advertised by ``OPTIONS``;
- unencoded reflection of a benign canary (reflected-XSS candidate);
- open-redirect candidate (``Location`` to a reserved ``.invalid`` host);
- verbose error / stack-trace disclosure on a nonexistent path.

All requests are GET/OPTIONS, redirects are never followed, bodies are capped,
and the canary values are inert. Same defense in depth as the other workers:
ToolExecutor LAB_ACTIVE boundary plus an independent
:func:`lightup.labeval.assert_lab_target` check before any socket is opened.
A finding is a *candidate* with evidence, not proof of exploitability.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from http.client import HTTPConnection
from typing import Any
from urllib.parse import quote, urlparse

from ..ai.orchestration import (
    ParamKind,
    RunContext,
    ToolDefinition,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
)
from ..engagements import RiskLevel
from ..execution_policy import InteractionKind
from ..labeval import LabIsolationError, assert_lab_target
from ..models import Severity

TOOL_ID = "lab-web-exposure"
CAPABILITY_ID = "web-baseline"

PROBE_ORIGIN = "https://lightup-probe.invalid"
REDIRECT_PROBE = "https://lightup-redirect-probe.invalid/"
MAX_BODY_BYTES = 64 * 1024

# check_id -> (title, severity, impact, remediation)
WEB_EXPOSURE_CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "cookie-missing-httponly": (
        "Cookie without HttpOnly flag",
        Severity.MEDIUM,
        "Script running in the page (e.g. via XSS) can read the cookie and steal the session.",
        "Set the HttpOnly attribute on session and other sensitive cookies.",
    ),
    "cookie-missing-samesite": (
        "Cookie without SameSite attribute",
        Severity.LOW,
        "The cookie is attached to cross-site requests, easing CSRF.",
        "Set SameSite=Lax (or Strict) on cookies unless cross-site use is required.",
    ),
    "cors-reflected-origin": (
        "CORS reflects arbitrary origins",
        Severity.HIGH,
        "Any website can read authenticated responses cross-origin when "
        "credentials are also allowed; otherwise it widens data exposure.",
        "Validate Origin against an explicit allowlist; never echo it back blindly "
        "and never combine it with Access-Control-Allow-Credentials.",
    ),
    "cors-wildcard-origin": (
        "CORS allows any origin (wildcard)",
        Severity.LOW,
        "Any website can read this endpoint's unauthenticated responses.",
        "Restrict Access-Control-Allow-Origin to the origins that need access.",
    ),
    "exposed-git-metadata": (
        "Git repository metadata exposed",
        Severity.HIGH,
        "Source code, history and embedded secrets can be reconstructed from /.git/.",
        "Block access to dot-directories at the web server and remove .git from deployments.",
    ),
    "exposed-env-file": (
        "Environment file exposed",
        Severity.CRITICAL,
        "Credentials and API keys in /.env are downloadable by anyone.",
        "Remove the file from the web root, block dotfiles, and rotate every exposed secret.",
    ),
    "directory-listing-enabled": (
        "Directory listing enabled",
        Severity.MEDIUM,
        "Attackers can enumerate files, backups and internal artifacts.",
        "Disable automatic directory indexes and serve an explicit index or 403.",
    ),
    "risky-http-methods-enabled": (
        "Risky HTTP methods advertised",
        Severity.MEDIUM,
        "TRACE, PUT or DELETE enabled on a web target can enable cross-site "
        "tracing or unauthorized content modification.",
        "Allow only the methods the application needs (typically GET, HEAD, POST).",
    ),
    "reflected-input-unencoded": (
        "Query input reflected without output encoding",
        Severity.HIGH,
        "Markup characters in a parameter reach the page unencoded, a "
        "reflected cross-site scripting candidate.",
        "HTML-encode reflected values contextually and add a restrictive CSP.",
    ),
    "open-redirect-candidate": (
        "Open redirect candidate",
        Severity.MEDIUM,
        "Attackers can craft trusted-looking links that forward victims to arbitrary sites.",
        "Redirect only to relative paths or an allowlist of destinations.",
    ),
    "verbose-error-disclosure": (
        "Verbose error / stack trace disclosed",
        Severity.MEDIUM,
        "Stack traces reveal frameworks, file paths and internals that guide further attacks.",
        "Return generic error pages in production and log details server-side only.",
    ),
}

_LISTING_RE = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /", re.IGNORECASE)
_ENV_LINE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", re.MULTILINE)
_TRACE_MARKERS = ("Traceback (most recent call last)", "at java.", "System.NullReferenceException",
                  "Stack trace:", "node_modules/", "Fatal error:", "Whoops, looks like")


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


# --- pure evaluators (no I/O) ---------------------------------------------

def evaluate_cookies(response: Response) -> set[str]:
    found: set[str] = set()
    for cookie in response.header_all("Set-Cookie"):
        attrs = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
        if "httponly" not in attrs:
            found.add("cookie-missing-httponly")
        if "samesite" not in attrs:
            found.add("cookie-missing-samesite")
    return found


def evaluate_cors(response: Response, probe_origin: str = PROBE_ORIGIN) -> set[str]:
    acao = (response.header("Access-Control-Allow-Origin") or "").strip()
    if acao == probe_origin:
        return {"cors-reflected-origin"}
    if acao == "*":
        return {"cors-wildcard-origin"}
    return set()


def evaluate_git(response: Response) -> set[str]:
    if response.status == 200 and response.body.lstrip().startswith("ref:"):
        return {"exposed-git-metadata"}
    return set()


def evaluate_env(response: Response) -> set[str]:
    if response.status == 200 and len(_ENV_LINE_RE.findall(response.body)) >= 2:
        return {"exposed-env-file"}
    return set()


def evaluate_listing(response: Response) -> set[str]:
    if response.status == 200 and _LISTING_RE.search(response.body):
        return {"directory-listing-enabled"}
    return set()


def evaluate_methods(response: Response) -> set[str]:
    allow = (response.header("Allow") or "") + "," + (response.header("Access-Control-Allow-Methods") or "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    return {"risky-http-methods-enabled"} if methods & {"TRACE", "PUT", "DELETE"} else set()


def evaluate_reflection(response: Response, canary: str) -> set[str]:
    # Raw angle brackets around the canary surviving means no HTML encoding.
    if f"<{canary}>" in response.body:
        return {"reflected-input-unencoded"}
    return set()


def evaluate_redirect(response: Response) -> set[str]:
    location = response.header("Location") or ""
    if 300 <= response.status < 400 and urlparse(location).hostname == urlparse(REDIRECT_PROBE).hostname:
        return {"open-redirect-candidate"}
    return set()


def evaluate_error(response: Response) -> set[str]:
    if any(marker in response.body for marker in _TRACE_MARKERS):
        return {"verbose-error-disclosure"}
    return set()


# --- observation -------------------------------------------------------------

@dataclass(frozen=True)
class WebExposureObservation:
    url: str
    probes: tuple[tuple[str, int], ...]  # (probe name, HTTP status)
    issues: tuple[str, ...]  # check ids, sorted

    def to_json(self) -> str:
        return json.dumps({"url": self.url, "probes": dict(self.probes),
                           "issues": list(self.issues)}, sort_keys=True)


def _endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise LabIsolationError("the web exposure worker only speaks plain http to lab fixtures")
    host = assert_lab_target(url)
    return host, parsed.port or 80, parsed.path or "/"


def _request(host: str, port: int, method: str, path: str,
             headers: dict[str, str], timeout: float) -> Response:
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, headers={"User-Agent": "lightup-lab-web-exposure/0.1", **headers})
        response = connection.getresponse()
        body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
        return Response(response.status, tuple(response.getheaders()), body)
    finally:
        connection.close()


def observe(url: str, timeout: float = 5.0) -> WebExposureObservation:
    """Run the fixed probe set against one lab URL. Fails closed on non-lab targets."""
    host, port, base_path = _endpoint(url)
    canary = "lu" + secrets.token_hex(6)

    def get(path: str, **headers: str) -> Response:
        return _request(host, port, "GET", path, dict(headers), timeout)

    home = get(base_path, Origin=PROBE_ORIGIN)
    options = _request(host, port, "OPTIONS", base_path, {}, timeout)
    reflect_path = f"/?lightup_probe={quote(f'<{canary}>', safe='')}"
    reflect = get(reflect_path)
    redirect = get(f"/?next={quote(REDIRECT_PROBE, safe='')}&url={quote(REDIRECT_PROBE, safe='')}")
    missing = get(f"/lightup-probe-{canary}")
    git = get("/.git/HEAD")
    env = get("/.env")
    listing = get("/static/")

    issues = (evaluate_cookies(home) | evaluate_cors(home) | evaluate_git(git)
              | evaluate_env(env) | evaluate_listing(listing) | evaluate_methods(options)
              | evaluate_reflection(reflect, canary) | evaluate_redirect(redirect)
              | evaluate_error(missing))
    probes = (("home", home.status), ("options", options.status), ("reflect", reflect.status),
              ("redirect", redirect.status), ("missing", missing.status), ("git", git.status),
              ("env", env.status), ("listing", listing.status))
    return WebExposureObservation(url=url, probes=probes, issues=tuple(sorted(issues)))


def run_web_exposure(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    """ToolHandler: lab-only web exposure probes with defense-in-depth lab checks."""
    if not context.is_lab:
        raise LabIsolationError("the web exposure worker only runs in lab contexts")
    observation = observe(str(arguments["url"]))
    found = ", ".join(observation.issues) or "none"
    return ToolOutput(
        summary=f"Web exposure probes on {observation.url}: issues: {found}",
        evidence_kind="web-exposure-observation",
        evidence_payload=observation.to_json().encode("utf-8"),
        metadata=(("issues", ",".join(observation.issues)),),
    )


WEB_EXPOSURE_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Fixed non-destructive GET/OPTIONS probes against an isolated lab web "
                "target: cookies, CORS, exposed files, listing, methods, reflection, "
                "open redirect, error disclosure.",
    parameters=(ToolParameter("url", ParamKind.STRING, required=True,
                              description="Lab fixture URL (loopback/private, http only)"),),
)


def register(registry: ToolRegistry) -> None:
    registry.register(WEB_EXPOSURE_TOOL, run_web_exposure)
