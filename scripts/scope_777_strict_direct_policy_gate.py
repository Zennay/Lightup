"""Opt-in issue #777 strict fail-closed test gate for real policy imports.

Run from a checked-out LightUp repo with PYTHONPATH=src. Synthetic values only:
no real grants, network, executors, application mutation or release authority.
Unlike @expectedFailure tests, an observed direct-grant bypass returns exit 2.
"""
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind, PolicyDecision


class SpoofedText(str):
    pass


def _receipt(
    ok: bool, invalid_allowed: int | None,
    negative_allowed: int | None = None, negative_examined: int = 0,
) -> dict[str, object]:
    return {
        "status": "TEST_ONLY_PASS" if ok else "HOLD",
        "invalid_examined": 14 if invalid_allowed is not None else 0,
        "invalid_allowed": invalid_allowed,
        "negative_controls_examined": negative_examined,
        "negative_controls_allowed": negative_allowed,
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

    def check(request: ExecutionRequest) -> bool:
        # A green verdict must not hide a mutated request or grant. Type exactness
        # prevents bool-like or PolicyDecision-subclass return spoofing.
        original_request = dict(request.__dict__)
        # A shallow dict misses in-place mutation of nested ScopeDefinition:
        # both snapshots are needed to reject a policy that rewrites scope.
        immutable_snapshot = deepcopy(request)
        original_grant = (dict(request.authorization.__dict__)
                          if request.authorization is not None else None)
        result = policy.decide(request)
        if type(result) is not PolicyDecision or type(result.allowed) is not bool:
            raise ValueError("invalid policy decision contract")
        if request.__dict__ != original_request or request != immutable_snapshot:
            raise ValueError("request or nested scope mutated during policy decision")
        if original_grant is not None and request.authorization.__dict__ != original_grant:
            raise ValueError("grant mutated during policy decision")
        return result.allowed

    def target(g: AuthorizationGrant | None, *, asset: str = "example.test",
               capability: str = "fictional-check",
               risk: RiskLevel = RiskLevel.LOW_IMPACT) -> ExecutionRequest:
        return ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE, asset=asset,
            capability_id=capability, requested_risk=risk,
            authorization=g,
        )

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
    if check(target(grant)) is not True:
        return _receipt(False, None)
    allowed = 0
    for patch in variants:
        candidate = replace(grant, **patch)
        allowed += int(check(target(candidate)))

    # A production patch that denies bad provenance but widens other authority
    # boundaries must also FAIL. These cases are independent of #777's 14
    # direct-provenance failures and deliberately use valid approval fields.
    denied_requests = (
        target(None),
        target(replace(grant, valid_from=now-timedelta(days=3),
                       valid_until=now-timedelta(days=1))),
        target(replace(grant, valid_from=now+timedelta(hours=2),
                       valid_until=now+timedelta(hours=3))),
        target(grant, asset="other.example.test"),
        target(replace(grant, scope=replace(grant.scope,
                           excluded_assets=("example.test",)))),
        target(grant, capability="unapproved-check"),
        target(grant, risk=RiskLevel.ELEVATED),
        target(grant, risk=RiskLevel.DESTRUCTIVE_LAB_ONLY),
        ExecutionRequest(interaction=InteractionKind.LAB_ACTIVE,
                         asset="example.test", capability_id="fictional-check",
                         requested_risk=RiskLevel.LOW_IMPACT, is_lab=False),
        ExecutionRequest(interaction=InteractionKind.ANALYSIS,
                         asset="example.test", capability_id="fictional-check",
                         requested_risk=RiskLevel.LOW_IMPACT),
        ExecutionRequest(interaction=InteractionKind.PASSIVE_PUBLIC,
                         asset="example.test", capability_id="fictional-check",
                         requested_risk=RiskLevel.LOW_IMPACT),
    )
    negative_allowed = sum(int(check(request)) for request in denied_requests)
    # An analysis-only request is explicitly permitted and must remain so.
    analysis_control = ExecutionRequest(
        interaction=InteractionKind.ANALYSIS, asset="example.test",
        capability_id="fictional-check", requested_risk=RiskLevel.ANALYSIS_ONLY,
    )
    if check(analysis_control) is not True:
        return _receipt(False, allowed, negative_allowed, len(denied_requests))
    return _receipt(allowed == 0 and negative_allowed == 0, allowed,
                    negative_allowed, len(denied_requests))


def main() -> int:
    try:
        verdict = _scan_pure_local()
    except Exception:  # Never echo operator, grant, traceback, or test tokens.
        verdict = _receipt(False, None)
    print(json.dumps(verdict, sort_keys=True, separators=(",", ":")))
    return 0 if verdict["status"] == "TEST_ONLY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
