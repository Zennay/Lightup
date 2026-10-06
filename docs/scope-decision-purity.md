# Scope decision repeatability and input purity

Issue: #344

This branch-only proof freezes an evaluator property of the legacy scope gate without
changing any production authorization code.

## Contract

For canonical immutable inputs, repeated `ScopePolicy.decide()` calls must be
side-effect-free and deterministic:

- the same target/policy pair yields the same `ScopeDecision`;
- normalized host, allow/deny state, and reason remain stable;
- evaluation does not rewrite target value, labels, or attached authorization metadata;
- evaluation does not replace or rewrite canonical `explicit_hosts` or
  `explicit_networks` policy containers;
- an unknown public target remains denied across repeated evaluation.

The regression covers loopback, explicit-host, explicit-network, and denied
out-of-scope paths.

## Non-overlap with mutable-policy hardening

This proof is intentionally narrower than #294. It uses canonical immutable policy
containers and proves that the evaluator itself does not mutate them. It does not
claim that supplying a mutable set/list and then mutating that object externally is
safe; #294 owns that construction-time snapshot problem.

## Safety boundary

All cases are pure in-memory parsing and authorization decisions. They perform no
DNS lookup, socket/HTTP operation, target interaction, scanning, capability
execution, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.

## Collision boundary

Only these new files belong to this slice:

- `tests/test_scope_decision_purity.py`
- `docs/scope-decision-purity.md`

No existing source file, existing test file, activation/execution-policy/domain
surface, webapp, planner/orchestrator, or other scope-authorization lane is modified.
