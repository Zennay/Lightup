# Durable grant falsy evaluation-time acceptance

Tracked by #735.

## Boundary

`AuthorizationGrant.is_current(now=...)` must distinguish omission from malformed caller input.

`None` is the only omission sentinel. A supplied falsy value such as `False`, `0`, or an empty string is still caller input and must fail closed rather than being replaced with the wall clock.

## Required behavior

- `None` preserves the existing omitted-clock behavior;
- an exact built-in timezone-aware `datetime` preserves the existing explicit-clock behavior;
- `False`, `0`, and `""` are rejected with a controlled authorization-time validation error;
- no malformed supplied value may be silently converted into a different authorization instant.

Current source is expected RED for the three falsy-input cases because it uses `now = now or datetime.now(timezone.utc)`.

## Non-overlap

This is the durable-grant counterpart of legacy #403. #347 owns general window semantics, #734 owns polymorphic `datetime` subclass rejection, and #647 owns issuance/persistence datetime integrity.

Tests/docs only: no production source, domain resolver, execution policy, activation, orchestration, target-capable, evidence-remediation, deployment, verdict or attack-path code is modified.

## Safety

Temporal authorization-input narrowing only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authority widening.
