# Produced scope-decision immutability

Issue: #349

This branch-only proof freezes the post-decision mutation boundary of the legacy
scope evaluator. Once `ScopePolicy.decide()` has produced a value, callers must
not be able to widen or rewrite that same decision object in place.

## Contract

For both allowed and denied canonical decisions:

- `allowed` cannot be reassigned;
- `normalized_host` cannot be rewritten;
- `reason` cannot be rewritten;
- failed mutation attempts leave the original decision unchanged;
- repeated evaluation produces equal but independent immutable value objects.

The proof covers a denied unknown public target, an allowed loopback target, and
an explicit-host decision.

## Boundary

This contract does not claim that arbitrary direct construction or
`dataclasses.replace()` creates trustworthy authority. Those operations create
new values; downstream consumers remain responsible for their own coherence and
authorization gates. This proof only prevents post-evaluation in-place mutation
of the canonical result.

It is intentionally distinct from:

- #344, which proves evaluator input purity and repeatability;
- #346, which proves monotonicity when a policy is intentionally narrowed.

## Safety

All cases are pure in-memory value-object checks. They perform no DNS lookup,
socket/HTTP operation, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.

## Collision boundary

Only these new files belong to this slice:

- `tests/test_scope_decision_immutability.py`
- `docs/scope-decision-immutability.md`

No production source, existing regression, planner/orchestrator,
activation/execution-policy/domain surface, webapp, or other scope-authorization
lane is modified.
