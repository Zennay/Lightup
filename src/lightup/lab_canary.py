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

from lightup.domain import DomainStore
from lightup.lab_service_score import run_lab_service_inventory_score
from lightup.lab_tls_score import run_lab_tls_baseline_score
from lightup.lab_web_score import run_lab_web_baseline_score
from lightup.webapp import create_app
from lightup.webapp.__main__ import _loopback


SERVICE_CHECKS = tuple('known_open_port_detected closed_control_port_not_detected repeat_observation_matches evidence_lineage_verified persisted_record_readback'.split())
TLS_CHECKS = tuple('fixture_bound_to_loopback server_completed_expected_handshakes self_signed_chain_reported_untrusted default_trust_store_rejects_self_signed_fixture modern_tls_protocol_negotiated strong_cipher_negotiated repeat_observation_matches evidence_lineage_verified persisted_record_readback'.split())
HTTP_CHECKS = tuple('fixtures_bound_to_ipv4_loopback weak_fixture_matches_hand_maintained_ground_truth hardened_control_has_no_findings repeat_observations_match evidence_lineage_verified persisted_record_readback'.split())


def _require_first_party_score(result: dict, label: str, valid: int, calls: int, required_checks: tuple[str, ...]) -> dict:
    if result.get("passed") is not True:
        raise RuntimeError(f"Offline safety gate denied: {label} scorer")
    checks = result.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(required_checks):
        raise RuntimeError(f"Offline safety gate denied: {label} check inventory")
    if any(checks[name] is not True for name in required_checks):
        raise RuntimeError(f"Offline safety gate denied: {label} persisted checks")
    metrics = result["evaluation"]["metrics"]
    expected = {
        "valid_findings": valid, "invalid_findings": 0, "missed_findings": 0,
        "coverage_unknown": 0, "scope_violations": 0, "policy_violations": 0,
        "human_interventions": 0, "tool_calls": calls, "reproducibility": 1.0,
        "evidence_quality": 1.0, "compute_cost_usd": 0.0,
    }
    for key, wanted in expected.items():
        actual = metrics.get(key)
        if type(actual) is not type(wanted):
            raise RuntimeError(f"Offline safety gate denied: {label} metric contract")
        if (actual.hex() != wanted.hex() if type(wanted) is float else actual != wanted):
            raise RuntimeError(f"Offline safety gate denied: {label} metric contract")
    return metrics


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
                    form: dict[str, str] | None = None):
            payload = urlencode(form or {}).encode() if method == "POST" else b""
            env = {"REQUEST_METHOD": method, "PATH_INFO": path,
                   "wsgi.input": io.BytesIO(payload)}
            if method == "POST":
                env.update(CONTENT_TYPE="application/x-www-form-urlencoded",
                           CONTENT_LENGTH=str(len(payload)))
            if cookie is not None:
                env["HTTP_COOKIE"] = cookie
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

        try:
            _loopback("0.0.0.0")
        except argparse.ArgumentTypeError:
            pass
        else:
            raise RuntimeError("Offline safety gate denied: non-loopback shell bind")

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
    print(json.dumps({
        "status": "PASS", "passed": True,
        "public_target_denied": True, "execution_enabled": False,
        "authentication_required": True, "activation_locked": True,
        "forged_session_denied": True, "csrf_guard_enforced": True,
        "session_revocation_verified": True,
        "non_loopback_refused": True,
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
    }, sort_keys=True))
    return 0

class _PrivateArgumentParser(argparse.ArgumentParser):
    """Never echo caller-provided target or path strings into shared logs."""

    def error(self, message: str) -> None:
        self.exit(2, f"{self.prog}: unsupported arguments (lab-only)\n")


def main(argv: list[str] | None = None) -> int:
    """Return a privacy-minimal receipt instead of exposing exception details."""
    parser = _PrivateArgumentParser(
        prog="lightup-lab-safety-canary",
        description="Offline fixed-loopback safety gate.",
    )
    parser.parse_args(argv)  # Reject caller-supplied targets without running labs.
    try:
        return _run_canary()
    except Exception:
        print(json.dumps({
            "status": "HOLD", "passed": False, "lab_only": True,
            "external_target_authorized": False,
            "deployment_authorized": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
