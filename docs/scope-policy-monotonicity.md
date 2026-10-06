# Scope policy narrowing monotonicity

Issue: #346

This branch-only proof freezes a fail-closed property of the legacy scope gate:
intentionally making a canonical scope policy stricter must never create new
authority.

## Contract

For the same target identity:

- removing an explicit host cannot turn a denial into an allow;
- removing an explicit CIDR cannot turn a denial into an allow;
- requiring public authorization where it was previously optional can only
  preserve or reduce public authority;
- disabling the private-lab shortcut can only preserve or reduce authority;
- narrowing unrelated allowlist entries leaves an already denied target denied;
- normalization of the target identity remains stable while policy authority is
  reduced.

The regression deliberately compares a broader policy with a newly constructed
narrower policy. It does not mutate an existing policy object and therefore does
not overlap construction-time mutable-container hardening (#294).

## Relationship to #344

#344 proves that repeated evaluation of one canonical policy is deterministic and
input-pure. This issue proves a different property: when an operator intentionally
constructs a stricter policy, the resulting scope decision is monotonic toward
denial rather than authority expansion.

## Safety boundary

All cases are pure in-memory scope decisions. They perform no DNS lookup,
socket/HTTP operation, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.

## Collision boundary

Only these new files belong to this slice:

- `tests/test_scope_policy_monotonicity.py`
- `docs/scope-policy-monotonicity.md`

No production source, existing regression, activation/execution-policy/domain
surface, planner/orchestrator, webapp, or other scope-authorization lane is
modified.
