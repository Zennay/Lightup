"""Canonical PASS admission for fixed first-party M1 loopback scorers.

Used by installed standalone scorer CLIs and the combined offline safety gate.
No caller-selected target or scenario may change these source-defined contracts.
"""
from __future__ import annotations

import math

SERVICE_CHECKS = tuple('known_open_port_detected closed_control_port_not_detected repeat_observation_matches evidence_lineage_verified persisted_record_readback'.split())
TLS_CHECKS = tuple('fixture_bound_to_loopback server_completed_expected_handshakes self_signed_chain_reported_untrusted default_trust_store_rejects_self_signed_fixture modern_tls_protocol_negotiated strong_cipher_negotiated repeat_observation_matches evidence_lineage_verified persisted_record_readback'.split())
HTTP_CHECKS = tuple('fixtures_bound_to_ipv4_loopback weak_fixture_matches_hand_maintained_ground_truth hardened_control_has_no_findings repeat_observations_match evidence_lineage_verified persisted_record_readback'.split())


def require_first_party_score(result: dict, label: str, valid: int, calls: int, required_checks: tuple[str, ...]) -> dict:
    if result.get("passed") is not True:
        raise RuntimeError(f"Offline safety gate denied: {label} scorer")
    checks = result.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(required_checks):
        raise RuntimeError(f"Offline safety gate denied: {label} check inventory")
    if any(checks[name] is not True for name in required_checks):
        raise RuntimeError(f"Offline safety gate denied: {label} persisted checks")
    evaluation = result["evaluation"]
    for key, result_key in (
        ("run_id", "run_id"),
        ("scenario_id", "scenario_id"),
        ("record_id", "evaluation_record_id"),
    ):
        linked = evaluation.get(key)
        if (type(linked) is not str or not linked.strip()
                or linked != result.get(result_key)):
            raise RuntimeError(f"Offline safety gate denied: {label} evaluation lineage")
    metrics = evaluation["metrics"]
    expected = {
        "valid_findings": valid, "invalid_findings": 0, "missed_findings": 0,
        "coverage_unknown": 0, "scope_violations": 0, "policy_violations": 0,
        "human_interventions": 0, "tool_calls": calls, "reproducibility": 1.0,
        "evidence_quality": 1.0, "compute_cost_usd": 0.0,
        "false_positive_rate": 0.0, "coverage_assessed": 1,
        "remediation_quality": 0.0, "retest_correctness": 0.0,
    }
    if type(metrics) is not dict or set(metrics) != set(expected) | {"runtime_seconds"}:
        raise RuntimeError(f"Offline safety gate denied: {label} metric inventory")
    duration = metrics["runtime_seconds"]
    if (type(duration) is not float or not math.isfinite(duration)
            or math.copysign(1.0, duration) < 0):
        raise RuntimeError(f"Offline safety gate denied: {label} runtime metric")
    for key, wanted in expected.items():
        actual = metrics.get(key)
        if type(actual) is not type(wanted):
            raise RuntimeError(f"Offline safety gate denied: {label} metric contract")
        if (actual.hex() != wanted.hex() if type(wanted) is float else actual != wanted):
            raise RuntimeError(f"Offline safety gate denied: {label} metric contract")
    return metrics

