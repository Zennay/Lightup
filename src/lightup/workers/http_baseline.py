"""Lab-only HTTP security-header baseline worker.

This is the first real capability worker: one HTTP GET against an **isolated
lab target**, evaluated for defensive response headers. It exists to prove the
whole chain — typed tool call → policy gate → worker → evidence ledger →
findings → lab evaluation — not to scan anything real.

Network access is gated in depth:

1. callers only reach the handler through the ToolExecutor, whose lab boundary
   and ExecutionPolicy refuse non-lab contexts;
2. the handler itself re-validates the target with
   :func:`lightup.labeval.assert_lab_target` and refuses non-lab run contexts,
   so even a mis-wired registry cannot point it at the internet;
3. only plain ``http`` to the already-validated loopback/private host is
   spoken, and redirects are never followed.
"""

from __future__ import annotations

import json
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

TOOL_ID = "lab-http-baseline"
CAPABILITY_ID = "web-baseline"

# check_id -> (header, title, severity, impact, remediation)
BASELINE_CHECKS: tuple[tuple[str, str, str, Severity, str, str], ...] = (
    (
        "missing-content-security-policy",
        "Content-Security-Policy",
        "Missing Content-Security-Policy header",
        Severity.MEDIUM,
        "Injected or third-party script can run unrestricted in visitors' browsers.",
        "Serve a restrictive Content-Security-Policy and tighten it per route.",
    ),
    (
        "missing-x-content-type-options",
        "X-Content-Type-Options",
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        "Browsers may MIME-sniff responses into executable content.",
        "Send `X-Content-Type-Options: nosniff` on every response.",
    ),
    (
        "missing-x-frame-options",
        "X-Frame-Options",
        "Missing clickjacking protection",
        Severity.LOW,
        "The page can be framed by other origins, enabling clickjacking.",
        "Send `X-Frame-Options: DENY` or a `frame-ancestors` CSP directive.",
    ),
    (
        "missing-referrer-policy",
        "Referrer-Policy",
        "Missing Referrer-Policy header",
        Severity.INFO,
        "Full URLs may leak to third parties through the Referer header.",
        "Send a restrictive Referrer-Policy such as `no-referrer`.",
    ),
    (
        "server-banner-disclosure",
        "Server",
        "Server software banner disclosed",
        Severity.INFO,
        "Version banners make it easier to match known exploits to the stack.",
        "Strip or genericize the Server header at the edge.",
    ),
)

# Cookie and CORS checks evaluated on the same single response. They cannot be
# header-presence checks: cookies repeat, and CORS depends on the probe Origin
# the worker sends. check_id -> (title, severity, impact, remediation).
# ``Secure`` is deliberately not checked: the lab speaks plain http only.
RESPONSE_POLICY_CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "cookie-missing-httponly": (
        "Cookie set without HttpOnly",
        Severity.MEDIUM,
        "Script running in the page can read the cookie, so a single XSS "
        "bug can steal the session.",
        "Set the HttpOnly attribute on every session cookie.",
    ),
    "cookie-missing-samesite": (
        "Cookie set without SameSite",
        Severity.LOW,
        "The cookie is sent on cross-site requests, widening CSRF exposure.",
        "Set `SameSite=Lax` or `SameSite=Strict` on session cookies.",
    ),
    "cors-wildcard-origin": (
        "CORS allows any origin",
        Severity.LOW,
        "Any website can read responses from this endpoint.",
        "Return an explicit allowlisted origin instead of `*`.",
    ),
    "cors-reflected-origin-with-credentials": (
        "CORS reflects arbitrary origin with credentials",
        Severity.HIGH,
        "Any website can make credentialed requests and read the "
        "authenticated response.",
        "Validate Origin against an allowlist; never reflect it while "
        "sending Access-Control-Allow-Credentials.",
    ),
}

PROBE_ORIGIN = "http://lightup-probe.invalid"


@dataclass(frozen=True)
class BaselineIssue:
    check_id: str
    title: str
    severity: Severity
    impact: str
    remediation: str


@dataclass(frozen=True)
class BaselineObservation:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    issues: tuple[BaselineIssue, ...]

    def to_json(self) -> str:
        return json.dumps(
            {
                "url": self.url,
                "status": self.status,
                "headers": dict(self.headers),
                "issues": [issue.check_id for issue in self.issues],
            },
            sort_keys=True,
        )


def evaluate_headers(headers: dict[str, str]) -> tuple[BaselineIssue, ...]:
    normalized = {name.lower(): value for name, value in headers.items()}
    issues: list[BaselineIssue] = []
    for check_id, header, title, severity, impact, remediation in BASELINE_CHECKS:
        present = header.lower() in normalized
        if check_id == "server-banner-disclosure":
            flagged = present and normalized[header.lower()].strip() != ""
        else:
            flagged = not present
        if flagged:
            issues.append(BaselineIssue(check_id, title, severity, impact, remediation))
    return tuple(issues)


def evaluate_response(
    headers: tuple[tuple[str, str], ...], probe_origin: str = PROBE_ORIGIN,
) -> tuple[BaselineIssue, ...]:
    """Header-presence checks plus cookie and CORS policy checks."""
    flagged: list[str] = []
    cookies = [value for name, value in headers if name.lower() == "set-cookie"]
    attrs = [{part.split("=", 1)[0].strip().lower() for part in cookie.split(";")[1:]}
             for cookie in cookies]
    if any("httponly" not in a for a in attrs):
        flagged.append("cookie-missing-httponly")
    if any("samesite" not in a for a in attrs):
        flagged.append("cookie-missing-samesite")
    first = {name.lower(): value.strip() for name, value in reversed(headers)}
    allow_origin = first.get("access-control-allow-origin")
    if allow_origin == "*":
        flagged.append("cors-wildcard-origin")
    elif (allow_origin == probe_origin
          and first.get("access-control-allow-credentials", "").lower() == "true"):
        flagged.append("cors-reflected-origin-with-credentials")
    extra = tuple(
        BaselineIssue(check_id, *RESPONSE_POLICY_CHECKS[check_id])
        for check_id in flagged
    )
    return evaluate_headers(dict(headers)) + extra


def _validated_lab_endpoint(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise LabIsolationError("the lab baseline only speaks plain http to lab fixtures")
    host = assert_lab_target(url)
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return host, port, path


def observe(url: str, timeout: float = 5.0) -> BaselineObservation:
    """Fetch one lab URL and evaluate its headers. Fails closed on non-lab targets."""
    host, port, path = _validated_lab_endpoint(url)
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"User-Agent": "lightup-lab-baseline/0.1",
                                              "Origin": PROBE_ORIGIN})
        response = connection.getresponse()
        headers = tuple((name, value) for name, value in response.getheaders())
        status = response.status
        response.read()
    finally:
        connection.close()
    issues = evaluate_response(headers)
    return BaselineObservation(url=url, status=status, headers=headers, issues=issues)


def run_http_baseline(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    """ToolHandler: lab-only HTTP baseline with defense-in-depth lab checks."""
    if not context.is_lab:
        raise LabIsolationError("the HTTP baseline worker only runs in lab contexts")
    observation = observe(str(arguments["url"]))
    missing = ", ".join(i.check_id for i in observation.issues) or "none"
    return ToolOutput(
        summary=(
            f"HTTP baseline on {observation.url}: status {observation.status}, "
            f"issues: {missing}"
        ),
        evidence_kind="http-baseline-observation",
        evidence_payload=observation.to_json().encode("utf-8"),
        metadata=(
            ("status", str(observation.status)),
            ("issues", ",".join(i.check_id for i in observation.issues)),
        ),
    )


HTTP_BASELINE_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Single HTTP GET against an isolated lab target; evaluates "
                "defensive response headers.",
    parameters=(ToolParameter("url", ParamKind.STRING, required=True,
                              description="Lab fixture URL (loopback/private, http only)"),),
)


def register(registry: ToolRegistry) -> None:
    registry.register(HTTP_BASELINE_TOOL, run_http_baseline)
