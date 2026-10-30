"""End-to-end labeval scoring for the TLS baseline worker.

The scorer owns a temporary self-signed HTTPS fixture bound exclusively to
127.0.0.1. It uses the real TLS worker through ToolExecutor, compares observed
issues with explicit hand-maintained ground truth, and persists an evidence-
bound evaluation record. It never accepts a caller-selected target.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from .lab_socket_guard import (PrivateLabArgumentParser, fixed_loopback_socket_boundary,
                               trusted_local_openssl)
from .lab_score_contract import TLS_CHECKS, require_first_party_score

from .ai.orchestration import ToolCall, ToolExecutor, ToolRegistry
from .labeval import (
    EvaluationMetrics,
    ExpectedFinding,
    LabEvaluationHarness,
    LabScenario,
    score_findings,
)
from .models import Severity
from .state import StateStore
from .workers import tls_baseline

LOOPBACK = "127.0.0.1"
SCENARIO_ID = "lab-tls-baseline-self-signed-loopback"
ENGINE_VERSION = "m1-tls-baseline"
EXPECTED_CHECK = "untrusted-certificate-chain"
_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "CBC")
# Four worker handshakes plus one independent strict-trust control.
_HANDSHAKES_PER_RUN = 5


def _create_self_signed_certificate(directory: Path) -> tuple[Path, Path]:
    """Create a short-lived self-signed certificate with a loopback IP SAN."""
    openssl = trusted_local_openssl()

    key_path = directory / "fixture-key.pem"
    cert_path = directory / "fixture-cert.pem"
    command = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # Never inherit operator-provided OpenSSL config/module/loader paths.
        # The fixed local certificate needs no child environment variables.
        env={},
        timeout=15,
        check=False,
    )
    if completed.returncode != 0 or not key_path.is_file() or not cert_path.is_file():
        raise RuntimeError("could not create the isolated loopback TLS fixture")
    key_path.chmod(0o600)
    cert_path.chmod(0o600)
    return cert_path, key_path


def _serve_fixture(
    listener: socket.socket,
    server_context: ssl.SSLContext,
    expected_connections: int,
    accepted: list[int],
    stop_requested: threading.Event,
) -> None:
    """Serve only the expected local handshakes; tolerate client trust rejection."""
    for _ in range(expected_connections):
        # Short accept polls allow an early producer failure to stop this
        # fixture before the enclosing network guard is removed. Retain
        # the original 8-second per-handshake upper bound.
        deadline = time.monotonic() + 8.0
        while not stop_requested.is_set():
            if time.monotonic() >= deadline:
                return
            try:
                client, _peer = listener.accept()
                break
            except socket.timeout:
                continue
            except OSError:
                return
        else:
            return
        if stop_requested.is_set():
            client.close()
            return
        accepted.append(1)
        try:
            client.settimeout(5.0)
            with server_context.wrap_socket(client, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            try:
                client.close()
            except OSError:
                pass


def _issue_ids(result) -> tuple[str, ...]:
    metadata = dict(result.metadata)
    return tuple(item for item in metadata.get("issues", "").split(",") if item)


def _default_trust_rejects_fixture(port: int) -> bool:
    """Independently verify that the system trust store rejects the fixture."""
    strict = ssl.create_default_context()
    try:
        with socket.create_connection((LOOPBACK, port), timeout=3.0) as raw:
            with strict.wrap_socket(raw, server_hostname=LOOPBACK):
                return False
    except ssl.SSLCertVerificationError:
        return True
    except (OSError, ssl.SSLError):
        return False


def _unprotected_run_lab_tls_baseline_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Run two TLS observations against a self-signed loopback fixture and score them."""
    with tempfile.TemporaryDirectory(prefix="lightup-tls-lab-") as temp_dir:
        cert_path, key_path = _create_self_signed_certificate(Path(temp_dir))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((LOOPBACK, 0))
            listener.listen(_HANDSHAKES_PER_RUN)
            listener.settimeout(0.2)
            host, port = listener.getsockname()
            if host != LOOPBACK:
                raise RuntimeError("TLS fixture did not bind exclusively to loopback")

            accepted: list[int] = []
            stop_requested = threading.Event()
            server_thread = threading.Thread(
                target=_serve_fixture,
                args=(listener, server_context, _HANDSHAKES_PER_RUN,
                      accepted, stop_requested),
                daemon=True,
            )
            server_thread.start()
            try:
                scenario = LabScenario(
                    scenario_id=SCENARIO_ID,
                    name="TLS baseline against an owned self-signed loopback fixture",
                    targets=(LOOPBACK,),
                    expected_findings=(
                        ExpectedFinding(
                            identifier=EXPECTED_CHECK,
                            title="Self-signed certificate chain is not trusted",
                            capability_id=tls_baseline.CAPABILITY_ID,
                            severity=Severity.MEDIUM.value,
                        ),
                    ),
                )
                state = StateStore(state_path)
                registry = ToolRegistry()
                tls_baseline.register(registry)
                executor = ToolExecutor(registry, state)
                harness = LabEvaluationHarness(engine_version=ENGINE_VERSION)
                context = harness.start_run(scenario)
                call = ToolCall(
                    tool_id=tls_baseline.TOOL_ID,
                    asset=LOOPBACK,
                    arguments=(("host", LOOPBACK), ("port", int(port))),
                )

                started = time.monotonic()
                observations = (
                    executor.execute(context, call),
                    executor.execute(context, call),
                )
                runtime = round(time.monotonic() - started, 4)
                default_trust_rejected = _default_trust_rejects_fixture(int(port))
                server_thread.join(timeout=10.0)
                server_completed = not server_thread.is_alive() and len(accepted) == _HANDSHAKES_PER_RUN

                first_issues = _issue_ids(observations[0])
                second_issues = _issue_ids(observations[1])
                first_metadata = dict(observations[0].metadata)
                second_metadata = dict(observations[1].metadata)
                protocols = (first_metadata.get("protocol", ""), second_metadata.get("protocol", ""))
                ciphers = (first_metadata.get("cipher", ""), second_metadata.get("cipher", ""))
                repeat_stable = (
                    first_issues == second_issues
                    and protocols[0] == protocols[1]
                    and ciphers[0] == ciphers[1]
                )
                expected = scenario.expected_findings or ()
                valid, invalid, missed = score_findings(expected, first_issues)

                evidence_ids = tuple(item.evidence_id for item in observations)
                evidence_rows = tuple(state.get_evidence(item) for item in evidence_ids)
                evidence_ok = len(set(evidence_ids)) == 2 and all(
                    row.run_id == context.run_id
                    and row.capability_id == tls_baseline.CAPABILITY_ID
                    and row.kind == "tls-baseline-observation"
                    and row.source == tls_baseline.TOOL_ID
                    and dict(row.metadata).get("is_lab") == "true"
                    for row in evidence_rows
                )
                exact_ground_truth = (
                    first_issues == (EXPECTED_CHECK,) and second_issues == (EXPECTED_CHECK,)
                )
                modern_protocol = all(protocol in {"TLSv1.2", "TLSv1.3"} for protocol in protocols)
                strong_cipher = all(
                    cipher
                    and cipher != "unknown"
                    and not any(marker in cipher.upper() for marker in _WEAK_CIPHER_MARKERS)
                    for cipher in ciphers
                )

                metrics = EvaluationMetrics(
                    valid_findings=valid,
                    invalid_findings=invalid,
                    missed_findings=missed,
                    coverage_assessed=1,
                    coverage_unknown=0,
                    evidence_quality=1.0 if evidence_ok else 0.0,
                    reproducibility=1.0 if repeat_stable else 0.0,
                    scope_violations=0,
                    policy_violations=0,
                    human_interventions=0,
                    tool_calls=len(observations),
                    runtime_seconds=runtime,
                )
                record = harness.record(
                    scenario,
                    context,
                    metrics,
                    notes=(
                        "Ground truth is the hand-maintained untrusted-certificate-chain check. "
                        "The self-signed certificate is generated ephemerally for 127.0.0.1; "
                        "the score is not evidence of external target authorization."
                    ),
                    evidence_ids=evidence_ids,
                )
                record_id = state.add_lab_evaluation(record.to_dict())
                persisted = state.get_lab_evaluation(record_id)

                checks = {
                    "fixture_bound_to_loopback": host == LOOPBACK and scenario.targets == (LOOPBACK,),
                    "server_completed_expected_handshakes": server_completed,
                    "self_signed_chain_reported_untrusted": exact_ground_truth,
                    "default_trust_store_rejects_self_signed_fixture": default_trust_rejected,
                    "modern_tls_protocol_negotiated": modern_protocol,
                    "strong_cipher_negotiated": strong_cipher,
                    "repeat_observation_matches": repeat_stable,
                    "evidence_lineage_verified": evidence_ok,
                    "persisted_record_readback": (
                        persisted["record_id"] == record_id
                        and persisted["run_id"] == context.run_id
                        and persisted["evidence_ids"] == list(evidence_ids)
                    ),
                }
                score = persisted["metrics"]
                passed = (
                    all(checks.values())
                    and score["valid_findings"] == 1
                    and score["invalid_findings"] == 0
                    and score["missed_findings"] == 0
                    and score["policy_violations"] == 0
                    and score["reproducibility"] == 1.0
                    and score["evidence_quality"] == 1.0
                )
                return {
                    "passed": passed,
                    "scenario_id": SCENARIO_ID,
                    "run_id": context.run_id,
                    "fixture_host": LOOPBACK,
                    "fixture_port": int(port),
                    "observed_protocols": list(protocols),
                    "observed_ciphers": list(ciphers),
                    "observed_issues": [list(first_issues), list(second_issues)],
                    "checks": checks,
                    "evaluation_record_id": record_id,
                    "evaluation": persisted,
                }

            finally:
                stop_requested.set()
                # A TLS handshake can take up to 5 seconds. Keep the
                # scoped loopback guard active until this owned thread stops.
                server_thread.join(timeout=6.0)
                if server_thread.is_alive():
                    raise RuntimeError("Offline TLS fixture thread did not stop")



def run_lab_tls_baseline_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Score one owned fixture with a strict in-process IPv4 loopback socket gate."""
    with fixed_loopback_socket_boundary():
        return _unprotected_run_lab_tls_baseline_score(state_path)


def main(argv: list[str] | None = None) -> int:
    parser = PrivateLabArgumentParser(
        prog="lightup-lab-tls-score",
        description="Score the TLS baseline worker against an owned self-signed loopback fixture.",
    )
    parser.add_argument(
        "--db",
        default="lightup-lab.db",
        help="SQLite evidence/evaluation database path (default: lightup-lab.db)",
    )
    args = parser.parse_args(argv)
    try:
        result = run_lab_tls_baseline_score(args.db)
        require_first_party_score(result, "TLS", 1, 2, TLS_CHECKS)
    except Exception:
        print(json.dumps({"passed": False, "error": "offline fixture denied or unavailable"}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
