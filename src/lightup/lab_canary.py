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

from lightup.domain import DomainStore
from lightup.lab_service_score import run_lab_service_inventory_score
from lightup.lab_tls_score import run_lab_tls_baseline_score
from lightup.lab_web_score import run_lab_web_baseline_score
from lightup.webapp import create_app
from lightup.webapp.__main__ import _loopback


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lightup-lab-safety-canary", description="Offline fixed-loopback safety gate.")
    parser.parse_args(argv)  # Caller cannot select a network target or database.
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

        def get(path: str, cookie: str | None = None):
            env = {
                "REQUEST_METHOD": "GET", "PATH_INFO": path,
                "wsgi.input": io.BytesIO(b""),
            }
            if cookie is not None:
                env["HTTP_COOKIE"] = cookie
            response = {}
            body = b"".join(app(
                env, lambda status, headers: response.update(
                    status=status, headers=dict(headers)
                )
            )).decode()
            return response["status"], response["headers"], body

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

        try:
            _loopback("0.0.0.0")
        except argparse.ArgumentTypeError:
            pass
        else:
            raise RuntimeError("Offline safety gate denied: non-loopback shell bind")

        service_score = run_lab_service_inventory_score(
            Path(directory) / "service-labeval.db"
        )
        if not (service_score["passed"]):
            raise RuntimeError("Offline safety gate denied: service scorer")
        service_metrics = service_score["evaluation"]["metrics"]
        if not ((
            service_metrics["valid_findings"],
            service_metrics["invalid_findings"],
            service_metrics["missed_findings"],
            service_metrics["reproducibility"],
            service_metrics["evidence_quality"],
        ) == (1, 0, 0, 1.0, 1.0)):
            raise RuntimeError("Offline safety gate denied: service findings and quality")
        if not (all(service_score["checks"].values())):
            raise RuntimeError("Offline safety gate denied: service persisted checks")

        tls_score = run_lab_tls_baseline_score(
            Path(directory) / "tls-labeval.db"
        )
        if not (tls_score["passed"]):
            raise RuntimeError("Offline safety gate denied: TLS scorer")
        tls_metrics = tls_score["evaluation"]["metrics"]
        if not ((
            tls_metrics["valid_findings"],
            tls_metrics["invalid_findings"],
            tls_metrics["missed_findings"],
            tls_metrics["reproducibility"],
            tls_metrics["evidence_quality"],
        ) == (1, 0, 0, 1.0, 1.0)):
            raise RuntimeError("Offline safety gate denied: TLS findings and quality")
        if not (all(tls_score["checks"].values())):
            raise RuntimeError("Offline safety gate denied: TLS persisted checks")

        score = run_lab_web_baseline_score(Path(directory) / "web-labeval.db")
        if not (score["passed"]):
            raise RuntimeError("Offline safety gate denied: HTTP scorer")
        score_metrics = score["evaluation"]["metrics"]
        if not ((
            score_metrics["valid_findings"],
            score_metrics["invalid_findings"],
            score_metrics["missed_findings"],
            score_metrics["reproducibility"],
            score_metrics["evidence_quality"],
        ) == (5, 0, 0, 1.0, 1.0)):
            raise RuntimeError("Offline safety gate denied: HTTP findings and quality")
        if not (all(score["checks"].values())):
            raise RuntimeError("Offline safety gate denied: HTTP persisted checks")

    if not (not Path(directory).exists()):
        raise RuntimeError("Offline safety gate denied: temporary-state cleanup")
    print(json.dumps({
        "public_target_denied": True, "execution_enabled": False,
        "authentication_required": True, "activation_locked": True,
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


if __name__ == "__main__":
    raise SystemExit(main())
