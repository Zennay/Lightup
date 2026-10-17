#!/usr/bin/env python3
"""Offline canonical ScopePolicy witness. A REVIEW_ONLY receipt never grants authority.

Only the built-in, deterministic, synthetic case matrix is admitted by the CLI.
No user targets, network I/O, grants, handlers, or production state are read/written.
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Import the installed checkout's real evaluator, not a lookalike test implementation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.models import Authorization, Target  # noqa: E402
from lightup.scope import ScopeDecision, ScopePolicy, ScopeReason  # noqa: E402

SCHEMA = "lightup.scope-offline-decision-witness.v1"
FALSE_AUTHORITY = {
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "dispatch_allowed": False,
    "scan_allowed": False,
    "deployment_allowed": False,
    "release_allowed": False,
}


@dataclass(frozen=True)
class WitnessCase:
    case_id: str
    target: Target
    policy: ScopePolicy
    expected_allowed: bool
    expected_host: str | None
    expected_reason: ScopeReason


def canonical_cases() -> tuple[WitnessCase, ...]:
    # Reserved synthetic hostname and local policy-only address strings. No DNS.
    sample_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-NOT-CONSENT")
    expired_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-EXPIRED", valid_until=datetime(2000, 1, 1, tzinfo=timezone.utc))
    future_auth = Authorization(owner="fictional-reviewer", reference="SYNTHETIC-NOT-YET", valid_from=datetime(2100, 1, 1, tzinfo=timezone.utc))
    host = "fixture.example.test"
    hosts = frozenset({host})
    cidrs = ("8.8.8.0/24",)
    return (
        WitnessCase("loopback-ip", Target("127.0.0.1"), ScopePolicy(), True, "127.0.0.1", ScopeReason.LOOPBACK),
        WitnessCase("loopback-name", Target("LOCALHOST."), ScopePolicy(), True, "localhost", ScopeReason.LOOPBACK),
        WitnessCase("private-lab", Target("10.22.33.44"), ScopePolicy(), True, "10.22.33.44", ScopeReason.PRIVATE_LAB),
        WitnessCase("private-disabled", Target("10.22.33.44"), ScopePolicy(allow_private_lab=False), False, "10.22.33.44", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("unknown-public", Target("8.8.8.8"), ScopePolicy(), False, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("explicit-host-no-consent", Target("HTTPS://FIXTURE.EXAMPLE.TEST/path"), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_MISSING),
        WitnessCase("explicit-host-synthetic-control", Target(host, authorization=sample_auth), ScopePolicy(explicit_hosts=hosts), True, host, ScopeReason.EXPLICIT_HOST),
        WitnessCase("explicit-network-no-consent", Target("8.8.8.8"), ScopePolicy(explicit_networks=cidrs), False, "8.8.8.8", ScopeReason.AUTHORIZATION_MISSING),
        WitnessCase("explicit-network-synthetic-control", Target("8.8.8.8", authorization=sample_auth), ScopePolicy(explicit_networks=cidrs), True, "8.8.8.8", ScopeReason.EXPLICIT_NETWORK),
        WitnessCase("host-removed-denies", Target(host, authorization=sample_auth), ScopePolicy(), False, host, ScopeReason.OUT_OF_SCOPE),
        WitnessCase("blank-target-denies", Target(" "), ScopePolicy(), False, None, ScopeReason.INVALID_TARGET),
        WitnessCase("explicit-host-expired", Target(host, authorization=expired_auth), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-host-not-yet", Target(host, authorization=future_auth), ScopePolicy(explicit_hosts=hosts), False, host, ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-cidr-expired", Target("8.8.8.8", authorization=expired_auth), ScopePolicy(explicit_networks=cidrs), False, "8.8.8.8", ScopeReason.AUTHORIZATION_EXPIRED),
        WitnessCase("explicit-host-no-auth-policy", Target(host), ScopePolicy(explicit_hosts=hosts, require_authorization_for_public=False), True, host, ScopeReason.EXPLICIT_HOST),
        WitnessCase("cidr-removed-denies", Target("8.8.8.8", authorization=sample_auth), ScopePolicy(), False, "8.8.8.8", ScopeReason.OUT_OF_SCOPE),
        WitnessCase("loopback-lab-disabled", Target("127.0.0.1"), ScopePolicy(allow_private_lab=False), True, "127.0.0.1", ScopeReason.LOOPBACK),
    )


def _receipt(status: str, reason: str, checked: int = 0, digest: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": SCHEMA,
        "status": status,
        "reason": reason,
        "checked": checked,
        **FALSE_AUTHORITY,
    }
    if digest is not None:
        result["synthetic_matrix_sha256"] = digest
    return result


def evaluate(cases: tuple[WitnessCase, ...] | None = None) -> dict[str, object]:
    """Evaluate only synthetic in-memory cases. Returns a non-authorizing result."""
    try:
        fixtures = canonical_cases() if cases is None else cases
        if type(fixtures) is not tuple or len(fixtures) != 17:
            return _receipt("HOLD", "invalid_witness_matrix")
        ids: set[str] = set()
        observed: list[list[object]] = []
        for case in fixtures:
            if (
                type(case) is not WitnessCase
                or type(case.case_id) is not str
                or not case.case_id.isascii()
                or not case.case_id
                or case.case_id in ids
                or type(case.target) is not Target
                or type(case.target.value) is not str
                or type(case.target.labels) is not tuple
                or any(type(label) is not str for label in case.target.labels)
                or (
                    case.target.authorization is not None
                    and (
                        type(case.target.authorization) is not Authorization
                        or type(case.target.authorization.owner) is not str
                        or type(case.target.authorization.reference) is not str
                        or any(
                            bound is not None and (
                                type(bound) is not datetime or bound.tzinfo is not timezone.utc
                            )
                            for bound in (
                                case.target.authorization.valid_from,
                                case.target.authorization.valid_until,
                            )
                        )
                    )
                )
                or type(case.policy) is not ScopePolicy
                or type(case.policy.allow_private_lab) is not bool
                or type(case.policy.require_authorization_for_public) is not bool
                or type(case.policy.explicit_hosts) is not frozenset
                or any(type(item) is not str for item in case.policy.explicit_hosts)
                or type(case.policy.explicit_networks) is not tuple
                or any(type(item) is not str for item in case.policy.explicit_networks)
                or type(case.expected_allowed) is not bool
                or (case.expected_host is not None and type(case.expected_host) is not str)
                or type(case.expected_reason) is not ScopeReason
            ):
                return _receipt("HOLD", "invalid_witness_matrix")
            ids.add(case.case_id)
            decision = case.policy.decide(case.target)
            if (
                type(decision) is not ScopeDecision
                or type(decision.allowed) is not bool
                or (decision.normalized_host is not None and type(decision.normalized_host) is not str)
                or type(decision.reason) is not ScopeReason
            ):
                return _receipt("HOLD", "invalid_decision_shape")
            if (
                decision.allowed is not case.expected_allowed
                or decision.normalized_host != case.expected_host
                or decision.reason is not case.expected_reason
            ):
                return _receipt("HOLD", "scope_policy_contract_drift")
            observed.append([case.case_id, decision.allowed, decision.normalized_host, decision.reason.value])
        raw = json.dumps(observed, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        return _receipt("REVIEW_ONLY", "canonical_synthetic_matrix_matches", len(fixtures), hashlib.sha256(raw).hexdigest())
    except Exception:
        # Never echo potentially sensitive input/exception data to the review channel.
        return _receipt("HOLD", "offline_witness_evaluation_failed")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    # Exact built-in admission happens before any caller-controlled equality/iteration.
    if type(args) is not list or len(args) != 1 or type(args[0]) is not str or args[0] != "--offline-lab-only":
        receipt = _receipt("HOLD", "explicit_offline_opt_in_required")
    else:
        receipt = evaluate()
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
