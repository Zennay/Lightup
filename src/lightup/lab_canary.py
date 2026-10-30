"""Offline activation/authentication canaries with per-invocation state.

Safe to repeat or run concurrently on a persistent self-hosted runner.
The labeval smoke owns temporary IPv4-loopback HTTP
fixtures only; no non-loopback target is contacted.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

from lightup.domain import DomainStore, Role
from lightup.lab_socket_guard import PrivateLabArgumentParser, fixed_loopback_socket_boundary
from lightup.lab_service_score import run_lab_service_inventory_score
from lightup.lab_tls_score import run_lab_tls_baseline_score
from lightup.lab_web_score import run_lab_web_baseline_score
from lightup.webapp import create_app
from lightup.webapp.__main__ import _loopback


from lightup.lab_score_contract import (
    SERVICE_CHECKS, TLS_CHECKS, HTTP_CHECKS,
    require_first_party_score as _require_first_party_score,
)


def _run_canary() -> int:
    denied = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "scope-check", "8.8.8.8"],
        capture_output=True, text=True, check=False,
    )
    if not (denied.returncode == 2):
        raise RuntimeError("Offline safety gate denied: public-target refusal exit")
    if not (json.loads(denied.stdout)["allowed"] is False):
        raise RuntimeError("Offline safety gate denied: public-target refusal result")
    plan = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "plan", "127.0.0.1"],
        capture_output=True, text=True, check=True,
    )
    if not (json.loads(plan.stdout)["execution_enabled"] is False):
        raise RuntimeError("Offline safety gate denied: non-executing plan")

    with tempfile.TemporaryDirectory(prefix="lightup-ci-") as directory:
        store = DomainStore(Path(directory) / "web.db")
        app = create_app(store)

        def request(method: str, path: str, cookie: str | None = None,
                    form: dict[str, str] | None = None,
                    headers: dict[str, str] | None = None):
            payload = urlencode(form or {}).encode() if method == "POST" else b""
            env = {"REQUEST_METHOD": method, "PATH_INFO": path,
                   "wsgi.input": io.BytesIO(payload)}
            if method == "POST":
                env.update(CONTENT_TYPE="application/x-www-form-urlencoded",
                           CONTENT_LENGTH=str(len(payload)))
            if cookie is not None:
                env["HTTP_COOKIE"] = cookie
            env.update(headers or {})
            response = {}
            body = b"".join(app(
                env, lambda status, headers: response.update(
                    status=status, headers=dict(headers)
                )
            )).decode()
            return response["status"], response["headers"], body

        def get(path: str, cookie: str | None = None):
            return request("GET", path, cookie)

        status, headers, _ = get("/")
        if not (status == "303 See Other" and headers["Location"] == "/login"):
            raise RuntimeError("Offline safety gate denied: login redirect")
        user = store.bootstrap_operator("ci@lightup.test", "CI", "ci-canary-password")
        token, _csrf = store.create_session(user.user_id)
        status, _, body = get("/", cookie=f"lightup_session={token}")
        if not (status == "200 OK"):
            raise RuntimeError("Offline safety gate denied: authenticated route")
        if not ("Locked" in body and "no real-target execution path" in body):
            raise RuntimeError("Offline safety gate denied: locked activation")

        forged, headers, _ = get("/", "lightup_session=forged-lab-token")
        if forged != "303 See Other" or headers.get("Location") != "/login":
            raise RuntimeError("Offline safety gate denied: forged session accepted")
        cookie = f"lightup_session={token}"
        rejected, _, _ = request("POST", "/logout", cookie, {"csrf": "invalid-lab-csrf"})
        if rejected != "403 Forbidden" or get("/", cookie)[0] != "200 OK":
            raise RuntimeError("Offline safety gate denied: CSRF boundary")
        logged_out, headers, _ = request("POST", "/logout", cookie, {"csrf": _csrf})
        if logged_out != "303 See Other" or headers.get("Location") != "/login":
            raise RuntimeError("Offline safety gate denied: logout")
        expired, headers, _ = get("/", cookie)
        if (expired != "303 See Other" or headers.get("Location") != "/login"
                or store.session_context(token) is not None):
            raise RuntimeError("Offline safety gate denied: revoked session")

        # Synthetic identities and requests exist only inside this temp DB.
        operator = store.context_for_user(user.user_id)
        a = store.create_client(operator, "Fictional Lab A")
        b = store.create_client(operator, "Fictional Lab B")
        user_a = store.create_user(operator, "a@lightup.test", "Lab A", Role.CLIENT_ADMIN, a.client_id)
        user_b = store.create_user(operator, "b@lightup.test", "Lab B", Role.CLIENT_ADMIN, b.client_id)
        client_token, client_csrf = store.create_session(user_a.user_id)
        client_cookie = f"lightup_session={client_token}"
        own_path, other_path = f"/portal/{a.client_id}", f"/portal/{b.client_id}"
        if get("/", client_cookie)[0] != "403 Forbidden":
            raise RuntimeError("Offline safety gate denied: client entered operator dashboard")
        own_status, _, own_body = get(own_path, client_cookie)
        if own_status != "200 OK" or "Fictional Lab A" not in own_body:
            raise RuntimeError("Offline safety gate denied: own-tenant portal")
        denied_status, _, denied_body = get(other_path, client_cookie)
        if denied_status != "403 Forbidden" or "Fictional Lab B" in denied_body:
            raise RuntimeError("Offline safety gate denied: cross-tenant read")
        form = {"csrf": client_csrf, "assets": "synthetic.example.test", "risk": "1"}
        cross_write, _, _ = request("POST", other_path + "/requests", client_cookie, form)
        if cross_write != "403 Forbidden":
            raise RuntimeError("Offline safety gate denied: cross-tenant write")
        denied_origin, _, _ = request(
            "POST", own_path + "/requests", client_cookie, form,
            {"HTTP_ORIGIN": "https://untrusted.invalid"}
        )
        denied_site, _, _ = request(
            "POST", own_path + "/requests", client_cookie, form,
            {"HTTP_SEC_FETCH_SITE": "cross-site"}
        )
        if denied_origin != "403 Forbidden" or denied_site != "403 Forbidden":
            raise RuntimeError("Offline safety gate denied: cross-origin request")
        if store.list_assessment_requests(store.context_for_user(user_a.user_id)):
            raise RuntimeError("Offline safety gate denied: cross-origin request persisted")

        own_write, own_headers, _ = request("POST", own_path + "/requests", client_cookie, form)
        if own_write != "303 See Other" or own_headers.get("Location") != own_path:
            raise RuntimeError("Offline safety gate denied: legitimate tenant write")
        a_requests = store.list_assessment_requests(store.context_for_user(user_a.user_id))
        b_requests = store.list_assessment_requests(store.context_for_user(user_b.user_id))
        if (len(a_requests) != 1 or a_requests[0].requested_assets !=
                ("synthetic.example.test",) or b_requests):
            raise RuntimeError("Offline safety gate denied: tenant request isolation")

        try:
            _loopback("0.0.0.0")
        except argparse.ArgumentTypeError:
            pass
        else:
            raise RuntimeError("Offline safety gate denied: non-loopback shell bind")

        with fixed_loopback_socket_boundary():
            service_score = run_lab_service_inventory_score(
                Path(directory) / "service-labeval.db"
            )
            service_metrics = _require_first_party_score(service_score, "service", 1, 2, SERVICE_CHECKS)

            tls_score = run_lab_tls_baseline_score(
                Path(directory) / "tls-labeval.db"
            )
            tls_metrics = _require_first_party_score(tls_score, "TLS", 1, 2, TLS_CHECKS)

            score = run_lab_web_baseline_score(Path(directory) / "web-labeval.db")
            score_metrics = _require_first_party_score(score, "HTTP", 5, 4, HTTP_CHECKS)

    if not (not Path(directory).exists()):
        raise RuntimeError("Offline safety gate denied: temporary-state cleanup")
    return {
        "status": "PASS", "passed": True,
        "public_target_denied": True, "execution_enabled": False,
        "authentication_required": True, "activation_locked": True,
        "forged_session_denied": True, "csrf_guard_enforced": True,
        "session_revocation_verified": True,
        "cross_tenant_portal_denied": True,
        "cross_tenant_request_denied": True,
        "own_tenant_request_saved": True,
        "client_operator_route_denied": True,
        "cross_origin_request_denied": True,
        "non_loopback_refused": True,
        "fixed_loopback_socket_boundary_enforced": True,
        "temporary_state_removed": True,
        "lab_only": True,
        "external_target_authorized": False,
        "deployment_authorized": False,
        "service_inventory_labeval_passed": service_score["passed"],
        "service_inventory_valid_findings": service_metrics["valid_findings"],
        "service_inventory_invalid_findings": service_metrics["invalid_findings"],
        "service_inventory_missed_findings": service_metrics["missed_findings"],
        "service_inventory_reproducibility": service_metrics["reproducibility"],
        "service_inventory_evidence_quality": service_metrics["evidence_quality"],
        "tls_baseline_labeval_passed": tls_score["passed"],
        "tls_baseline_valid_findings": tls_metrics["valid_findings"],
        "tls_baseline_invalid_findings": tls_metrics["invalid_findings"],
        "tls_baseline_missed_findings": tls_metrics["missed_findings"],
        "tls_baseline_reproducibility": tls_metrics["reproducibility"],
        "tls_baseline_evidence_quality": tls_metrics["evidence_quality"],
        "web_baseline_labeval_passed": score["passed"],
        "web_baseline_valid_findings": score_metrics["valid_findings"],
        "web_baseline_invalid_findings": score_metrics["invalid_findings"],
        "web_baseline_missed_findings": score_metrics["missed_findings"],
        "web_baseline_reproducibility": score_metrics["reproducibility"],
        "web_baseline_evidence_quality": score_metrics["evidence_quality"],
    }


def _render_text(result: dict) -> str:
    """Operator-facing output with no private artifacts or authority claims."""
    if result["status"] != "PASS":
        return "LightUp offline lab safety gate: HOLD\nNo external target or deployment authorized"
    return "\n".join((
        "LightUp offline lab safety gate: PASS",
        "Mode: FIXED LOOPBACK LAB; external execution: DISABLED",
        "Scorer sockets: fixed IPv4 loopback only (in-process guard)",
        "Authentication, CSRF and session revocation: PASS",
        "Client isolation, operator roles and origin boundaries: PASS",
        f"Service scorer: PASS (synthetic valid findings: {result['service_inventory_valid_findings']})",
        f"TLS scorer: PASS (synthetic valid findings: {result['tls_baseline_valid_findings']})",
        f"HTTP scorer: PASS (synthetic valid findings: {result['web_baseline_valid_findings']})",
        "Ephemeral state: REMOVED",
        "External target and deployment authority: NONE",
    ))


def main(argv: list[str] | None = None) -> int:
    """Return a privacy-minimal receipt instead of exposing exception details."""
    parser = PrivateLabArgumentParser(
        prog="lightup-lab-safety-canary",
        description="Offline fixed-loopback safety gate.",
    )
    parser.add_argument("--format", choices=("json", "text"), default="json",
                        help="Output one machine-readable JSON receipt or a private-safe summary")
    args = parser.parse_args(argv)  # No caller-supplied target is supported.
    exit_code = 0
    try:
        result = _run_canary()
    except Exception:
        exit_code = 2
        result = {
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False, "deployment_authorized": False,
        }
    print(_render_text(result) if args.format == "text" else json.dumps(result, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
