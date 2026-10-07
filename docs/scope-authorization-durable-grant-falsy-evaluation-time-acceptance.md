# Durable grant malformed evaluation-time acceptance

Tracked by #735.

## Boundary

`AuthorizationGrant.is_current(now=...)` must distinguish omission from malformed caller input.

`None` is the only omission sentinel. Every supplied non-`datetime` value is still explicit caller input and must fail closed rather than being replaced with the wall clock or leaking an incidental attribute/type error.

## Required behavior

Canonical controls:

- `None` preserves the existing omitted-clock behavior;
- an exact built-in timezone-aware `datetime` preserves the existing explicit-clock behavior.

Malformed explicit inputs must all produce a controlled authorization-time `ValueError`:

- falsy `False`;
- falsy `0`;
- falsy empty text;
- truthy positive integer;
- truthy non-empty text;
- an arbitrary plain object.

Current source is expected RED for exactly **6** malformed-input methods. The three falsy shapes are silently replaced because source uses `now = now or datetime.now(timezone.utc)`; the three truthy non-datetime shapes reach incidental attribute access instead of the controlled validation boundary.

## Non-overlap

This is the durable-grant counterpart of legacy #403. #347 owns general window semantics, #734 owns polymorphic `datetime` subclass rejection, and #647 owns issuance/persistence datetime integrity.

Tests/docs only: no production source, domain resolver, execution policy, activation, orchestration, target-capable, evidence-remediation, deployment, verdict or attack-path code is modified.

## Safety

Temporal authorization-input narrowing only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authority widening.
