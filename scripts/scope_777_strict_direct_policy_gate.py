"""Opt-in issue #777 strict fail-closed test gate for real policy imports.

Run from a checked-out LightUp repo with PYTHONPATH=src. Synthetic values only:
no real grants, network, executors, application mutation or release authority.
Unlike @expectedFailure tests, an observed direct-grant bypass returns exit 2.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision


class SpoofedText(str):
    pass


def _receipt(ok: bool, invalid_allowed: int | None) -> dict[str, object]:
    return {
        "status": "TEST_ONLY_PASS" if ok else "HOLD",
        "invalid_examined": 14 if invalid_allowed is not None else 0,
        "invalid_allowed": invalid_allowed,
        "authorization_verified": False,
        "permit_issued": False,
        "dispatch_enabled": False,
        "merge_approved": False,
        "deploy_approved": False,
        "release_approved": False,
    }


def _scan_pure_local() -> dict[str, object]:
    now = datetime.now(timezone.utc)
    grant = AuthorizationGrant(
        grant_id="synthetic", client_id="synthetic", engagement_id="synthetic",
        approved_by="fictional-operator", reference="ROE-FICTIONAL",
        scope=ScopeDefinition(assets=("example.test",), max_risk=RiskLevel.LOW_IMPACT,
                              allowed_capabilities=("fictional-check",)),
        valid_from=now-timedelta(hours=1), valid_until=now+timedelta(hours=1),
    )
    policy = ExecutionPolicy()

    def decide(g: AuthorizationGrant) -> PolicyDecision:
        return policy.decide(ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE, asset="example.test",
            capability_id="fictional-check", requested_risk=RiskLevel.LOW_IMPACT,
            authorization=g,
        ))

    variants = (
        {"approved_by": ""}, {"approved_by": " \t "},
        {"approved_by": " fictional-operator "},
        {"approved_by": SpoofedText("fictional-operator")},
        {"approved_by": b"fictional-operator"}, {"approved_by": None},
        {"approved_by": "\u2003fictional-operator"},
        {"reference": ""}, {"reference": " \t "},
        {"reference": " ROE-FICTIONAL "},
        {"reference": SpoofedText("ROE-FICTIONAL")},
        {"reference": 123}, {"reference": None},
        {"reference": "ROE-FICTIONAL\u00a0"},
    )
    canonical = decide(grant)
    if type(canonical) is not PolicyDecision or canonical.allowed is not True:
        return _receipt(False, None)
    allowed = 0
    for patch in variants:
        candidate = replace(grant, **patch)
        before = candidate.__dict__.copy()
        decision = decide(candidate)
        if type(decision) is not PolicyDecision or type(decision.allowed) is not bool:
            return _receipt(False, None)
        if candidate.__dict__ != before:
            return _receipt(False, None)
        allowed += int(decision.allowed)
    return _receipt(allowed == 0, allowed)


def main() -> int:
    try:
        verdict = _scan_pure_local()
    except Exception:  # Never echo operator, grant, traceback, or test tokens.
        verdict = _receipt(False, None)
    print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
    return 0 if verdict["status"] == "TEST_ONLY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
