# ST5 remediation/retest-plan live-validator exact-object acceptance

Tracking: #784.

## Boundary

This acceptance slice is pinned directly above exact PR #190 head
`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

It owns only the input object-identity contract at
`validate_future_security_remediation_retest_plan_handoff()`.

## Required invariant

The live handoff validator must accept the exact canonical
`FutureSecurityRemediationRetestPlan` produced from live ST4 lineage and reject
producer-impossible subclasses before equality comparison with the rebuild.

The current broad `isinstance(...)` gate allows a subclass to supply custom
equality/inequality behavior. The acceptance regression therefore covers:

- exact canonical producer output as the green control;
- an equality/inequality-spoofing plan subclass;
- the same subtype carrying `execution_allowed=true`;
- caller-object preservation after rejection;
- no mutation of durable `runs`, `capability_leases`, or `evidence` rows.

The validator returns the canonical rebuilt plan, so this is a fail-closed
integrity boundary and not an execution/remediation-authority bypass.

## Non-overlap

- #190 retains strict persisted-handoff and live-validator source ownership.
- #325 owns direct construction of plan/item structural invariants.
- #60 retains remediation-evidence-bundle ownership.
- #62 and its descendants retain evidence-collection consumer ownership.
- This slice does not change parsing, model calls, target-capable paths,
  remediation/retest execution, deployment, verdicts, or attack-path state.

## Safety

Tests are deterministic and in-process. No model/network/target interaction,
evidence collection, scanning, tool execution, remediation/retest execution,
deployment, future-state resolution, verdict creation, or attack-path mutation.
