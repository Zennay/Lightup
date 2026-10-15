"""Lab-only web configuration-hygiene worker.

Extends the header baseline with a broader set of defensive-configuration
checks that web servers commonly get wrong. All checks are read-only
observations of server behaviour on an isolated lab fixture; the worker never
sends payloads and never follows redirects.

Checks fall into three groups:

1. **Should-not-be-reachable paths.** A small, fixed list of
   development/metadata paths that must not be served from a production web
   root. Each hit requires a content signature AND must differ from a
   calibration request to a random path, so catch-all ("soft-404") servers do
   not produce false positives.
2. **Response hygiene.** Directory listing enabled, stack traces / debug mode
   leaking in the body, missing ``HttpOnly``/``SameSite`` on session cookies,
   and over-permissive CORS reflection.
3. **Method hygiene.** ``TRACE`` advertised in an ``OPTIONS`` ``Allow`` header.

Evidence records which signal matched, never the sensitive content itself:
dotenv findings store variable *names* only and cookie values are discarded.

Defense in depth matches the other lab workers: reachable only through the
ToolExecutor's LAB_ACTIVE boundary plus an independent
:func:`assert_lab_target` check, plain http to a validated loopback/private
host only, bodies capped at :data:`MAX_BODY`.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from http.client import HTTPConnection
from typing import Any
from urllib.parse import urlparse

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
USER_AGENT = "lightup-lab-web-exposure/0.1"
MAX_BODY = 64 * 1024
CORS_PROBE_ORIGIN = "http://lightup-cors-probe.invalid"

# check_id -> (title, severity, impact, remediation)
WEB_EXPOSURE_CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "exposed-scm-metadata": (
        "Source-control metadata served from the web root",
        Severity.HIGH,
        "Deployed working copies let a client reconstruct server-side sources.",
        "Deny version-control directories at the server and deploy build output only.",
    ),
    "exposed-dotenv": (
        "Environment file served from the web root",
        Severity.CRITICAL,
        "Dotenv files are a common place for configuration secrets to leak.",
        "Keep config files outside the web root, deny dotfiles, and rotate any exposed values.",
    ),
    "exposed-backup-artifact": (
        "Backup or archive artifact served from the web root",
        Severity.HIGH,
        "Archives and dumps left in the web root expose their full contents.",
        "Remove build/backup artifacts from served directories and block archive extensions.",
    ),
    "unauthenticated-diagnostics": (
        "Diagnostics/metrics endpoint reachable without authentication",
        Severity.HIGH,
        "Unauthenticated diagnostics endpoints disclose internal configuration and state.",
        "Require authentication for diagnostics endpoints or bind them to an internal interface.",
    ),
    "debug-mode-enabled": (
        "Application debug mode is enabled",
        Severity.MEDIUM,
        "Debug responses disclose internal paths, configuration and stack detail.",
        "Disable debug mode in the production configuration.",
    ),
    "stack-trace-disclosure": (
        "Unhandled error returns a stack trace in the response body",
        Severity.MEDIUM,
        "Stack traces disclose framework internals and server-side file paths.",
        "Return generic error pages and log details server-side only.",
    ),
    "directory-listing-enabled": (
        "Directory listing is enabled",
        Severity.LOW,
        "Automatic indexes disclose files that were not meant to be browsed.",
        "Disable automatic directory indexes at the web server.",
    ),
    "session-cookie-missing-httponly": (
        "Session cookie is missing the HttpOnly attribute",
        Severity.MEDIUM,
        "Cookies without HttpOnly are readable from client-side script.",
        "Set HttpOnly on all session cookies.",
    ),
    "session-cookie-missing-samesite": (
        "Session cookie is missing the SameSite attribute",
        Severity.LOW,
        "Without SameSite the cookie is sent on cross-site requests.",
        "Set SameSite=Lax or Strict on session cookies.",
    ),
    "permissive-cors-reflection": (
        "CORS reflects an arbitrary origin with credentials allowed",
        Severity.HIGH,
        "Reflecting any origin with credentials lets other sites make authenticated requests.",
        "Allow only an explicit origin allowlist; never reflect the Origin with credentials.",
    ),
    "trace-method-enabled": (
        "HTTP TRACE method is advertised",
        Severity.LOW,
        "TRACE echoes the request and can assist header-disclosure techniques.",
        "Disable the TRACE method at the web server.",
    ),
}

# Development/metadata paths that should not be served from a production root.
# path -> (check_id, body signature regex). Signatures keep matches specific.
_PATH_CHECKS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("/.git/config", "exposed-scm-metadata", re.compile(r"\[core\]|\[remote ", re.I)),
    ("/.git/HEAD", "exposed-scm-metadata", re.compile(r"ref:\s*refs/")),
    ("/.svn/entries", "exposed-scm-metadata", re.compile(r"^\d+\s*$|svn://", re.M)),
    ("/.env", "exposed-dotenv", re.compile(r"^[A-Z0-9_]+=", re.M)),
    ("/backup.zip", "exposed-backup-artifact", re.compile(r"^PK\x03\x04")),
    ("/backup.sql", "exposed-backup-artifact",
     re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I)),
    ("/actuator/health", "unauthenticated-diagnostics", re.compile(r'"status"\s*:')),
    ("/server-status", "unauthenticated-diagnostics", re.compile(r"Apache Server Status", re.I)),
    ("/debug/vars", "unauthenticated-diagnostics", re.compile(r'"cmdline"|"memstats"')),
)

_DEBUG_SIGNATURES = re.compile(
    r"Werkzeug Debugger|Whoops\\|DEBUG\s*=\s*True|"
    r" ?Django ?.{0,40}DEBUG|Traceback \(most recent call last\)|"
    r"Exception Value:|stack trace", re.I)
_LISTING_SIGNATURE = re.compile(r"Index of /|<title>Directory listing for", re.I)
_DOTENV_VAR = re.compile(r"^([A-Z0-9_]+)=", re.M)


@dataclass(frozen=True)
class ExposureIssue:
    check_id: str
    detail: str = ""


@dataclass(frozen=True)
class ExposureObservation:
    url: str
    issues: tuple[ExposureIssue, ...]
    checked_paths: tuple[str, ...]
    soft_404: bool

    def to_json(self) -> str:
        return json.dumps(
            {
                "url": self.url,
                "soft_404_calibrated": self.soft_404,
                "checked_paths": list(self.checked_paths),
                "issues": [{"check_id": i.check_id, "detail": i.detail}
                           for i in self.issues],
            },
            sort_keys=True,
        )


def _validated_lab_endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise LabIsolationError("the web exposure worker only speaks plain http to lab fixtures")
    host = assert_lab_target(url)
    return host, parsed.port or 80, (parsed.path or "/")


@dataclass
class _Fetch:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def headers_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


def _request(host: str, port: int, method: str, path: str,
             extra_headers: dict[str, str] | None = None,
             timeout: float = 5.0) -> _Fetch:
    connection = HTTPConnection(host, port, timeout=timeout)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    headers.update(extra_headers or {})
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        collected = tuple((name, value) for name, value in response.getheaders())
        body = response.read(MAX_BODY)
        return _Fetch(response.status, collected, body)
    finally:
        connection.close()


def _body_signature(body: bytes) -> str:
    import hashlib
    return hashlib.sha256(body).hexdigest()


def evaluate(host: str, port: int, root: str) -> ExposureObservation:
    issues: list[ExposureIssue] = []
    checked: list[str] = []

    # Calibration probe: a random path tells us how the server answers for
    # content that definitely does not exist (status + body fingerprint).
    calib_path = f"/{secrets.token_hex(12)}/lightup-calibration"
    calibration = _request(host, port, "GET", calib_path)
    checked.append(calib_path)
    calib_sig = _body_signature(calibration.body)
    soft_404 = calibration.status == 200

    def is_real_hit(fetch: _Fetch) -> bool:
        if fetch.status != 200:
            return False
        # A catch-all server returns the same body for everything; reject it.
        return _body_signature(fetch.body) != calib_sig

    for path, check_id, signature in _PATH_CHECKS:
        fetch = _request(host, port, "GET", path)
        checked.append(path)
        if not is_real_hit(fetch):
            continue
        text = fetch.body.decode("utf-8", "replace")
        if not signature.search(text) and not signature.search(fetch.body[:64].decode("latin-1")):
            continue
        detail = ""
        if check_id == "exposed-dotenv":
            names = sorted(set(_DOTENV_VAR.findall(text)))[:20]
            detail = f"variables: {', '.join(names)}" if names else ""
        issues.append(ExposureIssue(check_id, detail))

    # Root/document response hygiene.
    root_fetch = _request(host, port, "GET", root)
    checked.append(root)
    root_text = root_fetch.body.decode("utf-8", "replace")
    if _DEBUG_SIGNATURES.search(root_text):
        issues.append(ExposureIssue("debug-mode-enabled"))
    if _LISTING_SIGNATURE.search(root_text):
        issues.append(ExposureIssue("directory-listing-enabled"))

    # A deliberately malformed query often surfaces an unhandled error. We only
    # read the body; we never submit data or follow where it points.
    error_fetch = _request(host, port, "GET", f"{root}?lightup%ff=%ff")
    if error_fetch.status >= 500 and _DEBUG_SIGNATURES.search(
            error_fetch.body.decode("utf-8", "replace")):
        if not any(i.check_id == "debug-mode-enabled" for i in issues):
            issues.append(ExposureIssue("stack-trace-disclosure"))

    for cookie in root_fetch.headers_all("Set-Cookie"):
        attrs = {a.strip().lower() for a in cookie.split(";")[1:]}
        name = cookie.split("=", 1)[0].strip().lower()
        looks_session = any(tag in name for tag in ("sess", "sid", "auth", "token"))
        if not looks_session:
            continue
        if "httponly" not in attrs:
            issues.append(ExposureIssue("session-cookie-missing-httponly", f"cookie: {name}"))
        if not any(a.startswith("samesite") for a in attrs):
            issues.append(ExposureIssue("session-cookie-missing-samesite", f"cookie: {name}"))

    # CORS reflection: does the server echo an untrusted Origin with credentials?
    cors = _request(host, port, "GET", root, {"Origin": CORS_PROBE_ORIGIN})
    acao = cors.header("Access-Control-Allow-Origin")
    acac = (cors.header("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao in {CORS_PROBE_ORIGIN, "*"} and acac:
        issues.append(ExposureIssue("permissive-cors-reflection", f"reflected: {acao}"))

    # Advertised methods.
    options = _request(host, port, "OPTIONS", root)
    allow = (options.header("Allow") or "").upper()
    if "TRACE" in {m.strip() for m in allow.split(",")}:
        issues.append(ExposureIssue("trace-method-enabled"))

    # De-duplicate (e.g. two SCM paths map to one check) keeping first detail.
    unique: dict[tuple[str, str], ExposureIssue] = {}
    for issue in issues:
        unique.setdefault((issue.check_id, issue.detail), issue)
    return ExposureObservation(root_fetch.url if False else f"http://{host}:{port}{root}",
                               tuple(unique.values()), tuple(checked), soft_404)


def run_web_exposure(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    if not context.is_lab:
        raise LabIsolationError("the web exposure worker only runs in lab contexts")
    host, port, root = _validated_lab_endpoint(str(arguments["url"]))
    observation = evaluate(host, port, root)
    found = [i.check_id for i in observation.issues]
    note = " (soft-404 server: path checks suppressed)" if observation.soft_404 else ""
    return ToolOutput(
        summary=(f"web exposure on {observation.url}: "
                 f"{len(found)} issue(s): {', '.join(sorted(set(found))) or 'none'}{note}"),
        evidence_kind="web-exposure-observation",
        evidence_payload=observation.to_json().encode("utf-8"),
        metadata=(("issues", ",".join(sorted(set(found)))),
                  ("soft_404", "true" if observation.soft_404 else "false")),
    )


WEB_EXPOSURE_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Read-only web configuration-hygiene checks against an isolated "
                "lab target, with soft-404 calibration to suppress false positives.",
    parameters=(ToolParameter("url", ParamKind.STRING, required=True,
                              description="Lab fixture URL (loopback/private, http only)"),),
)


def register(registry: ToolRegistry) -> None:
    registry.register(WEB_EXPOSURE_TOOL, run_web_exposure)
