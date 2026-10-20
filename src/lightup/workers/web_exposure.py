"""Lab-only web exposure worker: leaked files, directory listing, CORS, cookies.

A handful of plain HTTP GETs against an **isolated lab target**. Every probe
is a read; nothing is written, brute-forced or exploited. Gating mirrors
:mod:`lightup.workers.http_baseline`: the ToolExecutor policy gate refuses
non-lab contexts, the handler re-validates the target as a lab target, only
``http`` is spoken and redirects are never followed.

Exposed-file checks require a content *signature* (e.g. ``ref:`` for
``.git/HEAD``), so a fixture that answers 200 for every path does not produce
false positives. Evidence records only status, size, a body SHA-256 and the
signature name: leaked file contents are never stored.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPConnection
from typing import Any, Callable
from urllib.parse import urlparse

from ..ai.orchestration import (
    ParamKind, RunContext, ToolDefinition, ToolOutput, ToolParameter, ToolRegistry,
)
from ..engagements import RiskLevel
from ..execution_policy import InteractionKind
from ..labeval import LabIsolationError, assert_lab_target
from ..models import Severity

TOOL_ID = "lab-web-exposure"
CAPABILITY_ID = "privacy-data"
PROBE_ORIGIN = "http://cross-origin.lightup.invalid"
_MAX_BODY = 64 * 1024

# check_id -> (title, severity, impact, remediation)
EXPOSURE_CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "exposed-git-metadata": (
        "Git repository metadata is publicly readable",
        Severity.HIGH,
        "Attackers can reconstruct source code, history and committed secrets.",
        "Block /.git at the web server and deploy build artifacts, not checkouts.",
    ),
    "exposed-env-file": (
        "Environment file (.env) is publicly readable",
        Severity.CRITICAL,
        "Credentials and API keys in the file are exposed to anyone.",
        "Remove .env from the web root, deny dotfiles and rotate every exposed secret.",
    ),
    "exposed-database-dump": (
        "Database dump is publicly downloadable",
        Severity.CRITICAL,
        "Bulk customer data and password hashes can be downloaded.",
        "Delete the dump from the web root and store backups in private storage.",
    ),
    "directory-listing-enabled": (
        "Directory listing enabled",
        Severity.MEDIUM,
        "File names and unlinked files become discoverable.",
        "Disable autoindex / directory listing on the web server.",
    ),
    "cors-arbitrary-origin": (
        "CORS reflects arbitrary origins",
        Severity.MEDIUM,
        "Any website can read responses from this origin in a visitor's browser.",
        "Allow-list exact trusted origins instead of reflecting the Origin header.",
    ),
    "cors-credentialed-arbitrary-origin": (
        "CORS reflects arbitrary origins with credentials",
        Severity.HIGH,
        "Any website can make authenticated requests as the visitor and read the result.",
        "Never combine reflected origins with Access-Control-Allow-Credentials: true.",
    ),
    "cookie-missing-secure": (
        "Cookie set without the Secure flag",
        Severity.LOW,
        "The cookie can be sent over plain HTTP and intercepted.",
        "Set the Secure attribute on every cookie.",
    ),
    "cookie-missing-httponly": (
        "Cookie set without the HttpOnly flag",
        Severity.MEDIUM,
        "Injected script can read the cookie and hijack the session.",
        "Set HttpOnly on session and authentication cookies.",
    ),
    "cookie-missing-samesite": (
        "Cookie set without a SameSite attribute",
        Severity.LOW,
        "The cookie rides along on cross-site requests, easing CSRF.",
        "Set SameSite=Lax (or Strict) on session cookies.",
    ),
}


def _git_head(body: bytes) -> bool:
    return re.match(rb"^(?:ref: refs/|[0-9a-f]{40}\s*$)", body.strip()) is not None


def _env_file(body: bytes) -> bool:
    lines = [line for line in body.splitlines() if line.strip() and not line.startswith(b"#")]
    if not lines:
        return False
    assignments = [line for line in lines if re.match(rb"^[A-Z][A-Z0-9_]*=", line)]
    return len(assignments) >= max(1, len(lines) // 2)


def _sql_dump(body: bytes) -> bool:
    return re.search(rb"(?i)\b(?:CREATE TABLE|INSERT INTO)\b", body[:8192]) is not None


# path -> (check_id, signature name, signature predicate)
PATH_PROBES: tuple[tuple[str, str, str, Callable[[bytes], bool]], ...] = (
    ("/.git/HEAD", "exposed-git-metadata", "git-head-ref", _git_head),
    ("/.env", "exposed-env-file", "env-assignments", _env_file),
    ("/backup.sql", "exposed-database-dump", "sql-ddl-or-dml", _sql_dump),
    ("/db.sql", "exposed-database-dump", "sql-ddl-or-dml", _sql_dump),
)
_LISTING = re.compile(rb"(?i)<title>\s*(?:index of /|directory listing for /)")


@dataclass(frozen=True)
class Probe:
    path: str
    status: int
    size: int
    body_sha256: str
    signature: str | None = None

    def to_dict(self) -> dict:
        return {"path": self.path, "status": self.status, "size": self.size,
                "body_sha256": self.body_sha256, "signature": self.signature}


@dataclass(frozen=True)
class ExposureObservation:
    url: str
    probes: tuple[Probe, ...]
    issues: tuple[str, ...]
    cors: dict[str, str]
    cookie_names: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps({
            "url": self.url,
            "probes": [probe.to_dict() for probe in self.probes],
            "issues": list(self.issues),
            "cors": self.cors,
            "cookie_names": list(self.cookie_names),
        }, sort_keys=True)


def _endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise LabIsolationError("the web exposure worker only speaks plain http to lab fixtures")
    host = assert_lab_target(url)
    return host, parsed.port or 80, (parsed.path or "/")


def _get(host: str, port: int, path: str, headers: dict[str, str], timeout: float):
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={
            "User-Agent": "lightup-lab-web-exposure/0.1", **headers})
        response = connection.getresponse()
        body = response.read(_MAX_BODY)
        return response.status, response.getheaders(), body
    finally:
        connection.close()


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def evaluate_cookies(set_cookie_values: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (issue ids, cookie names) for Set-Cookie header values."""
    issues: list[str] = []
    names: list[str] = []
    for value in set_cookie_values:
        name = value.split("=", 1)[0].strip()
        if not name:
            continue
        names.append(name)
        attributes = {part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]}
        for attribute, check_id in (("secure", "cookie-missing-secure"),
                                    ("httponly", "cookie-missing-httponly"),
                                    ("samesite", "cookie-missing-samesite")):
            if attribute not in attributes and check_id not in issues:
                issues.append(check_id)
    return tuple(issues), tuple(names)


def evaluate_cors(headers: dict[str, str]) -> str | None:
    allowed = headers.get("access-control-allow-origin", "").strip()
    if allowed != PROBE_ORIGIN:
        return None
    credentials = headers.get("access-control-allow-credentials", "").strip().lower()
    return ("cors-credentialed-arbitrary-origin" if credentials == "true"
            else "cors-arbitrary-origin")


def observe(url: str, timeout: float = 5.0) -> ExposureObservation:
    """Probe one lab base URL. Fails closed on non-lab targets."""
    host, port, base_path = _endpoint(url)
    issues: list[str] = []
    probes: list[Probe] = []

    status, raw_headers, body = _get(host, port, base_path, {"Origin": PROBE_ORIGIN}, timeout)
    headers = {name.lower(): value for name, value in raw_headers}
    probes.append(Probe(base_path, status, len(body), sha256(body).hexdigest(),
                        "directory-listing" if _LISTING.search(body) else None))
    if status == 200 and _LISTING.search(body):
        issues.append("directory-listing-enabled")
    cors_issue = evaluate_cors(headers)
    if cors_issue:
        issues.append(cors_issue)
    cookie_issues, cookie_names = evaluate_cookies(
        [value for name, value in raw_headers if name.lower() == "set-cookie"])
    issues.extend(cookie_issues)

    for path, check_id, signature, predicate in PATH_PROBES:
        probe_path = _join(base_path, path)
        status, _headers, body = _get(host, port, probe_path, {}, timeout)
        matched = status == 200 and predicate(body)
        probes.append(Probe(probe_path, status, len(body), sha256(body).hexdigest(),
                            signature if matched else None))
        if matched and check_id not in issues:
            issues.append(check_id)

    return ExposureObservation(
        url=url, probes=tuple(probes), issues=tuple(issues),
        cors={key: headers[key] for key in ("access-control-allow-origin",
                                            "access-control-allow-credentials")
              if key in headers},
        cookie_names=cookie_names,
    )


def run_web_exposure(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    """ToolHandler: lab-only exposure probes with defense-in-depth lab checks."""
    if not context.is_lab:
        raise LabIsolationError("the web exposure worker only runs in lab contexts")
    observation = observe(str(arguments["url"]))
    return ToolOutput(
        summary=(f"Web exposure on {observation.url}: {len(observation.probes)} probes, "
                 f"issues: {', '.join(observation.issues) or 'none'}"),
        evidence_kind="web-exposure-observation",
        evidence_payload=observation.to_json().encode("utf-8"),
        metadata=(
            ("probes", str(len(observation.probes))),
            ("issues", ",".join(observation.issues)),
        ),
    )


WEB_EXPOSURE_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Read-only HTTP GET probes against an isolated lab target for leaked "
                "files (.git, .env, SQL dumps), directory listing, CORS origin "
                "reflection and cookie flags.",
    parameters=(ToolParameter("url", ParamKind.STRING, required=True,
                              description="Lab fixture base URL (loopback/private, http only)"),),
)


def register(registry: ToolRegistry) -> None:
    registry.register(WEB_EXPOSURE_TOOL, run_web_exposure)
