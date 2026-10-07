# ST5 remediation evidence live-validator exact-object acceptance

Tracking: #782.

## Boundary

This acceptance slice pins to exact PR #194 head
`ec4b09f539289fbf3b497a534980323bd3c11bef`, which contains the #60
remediation-evidence producer and live validator unchanged.

It owns only the object-identity contract at
`validate_future_remediation_evidence_bundle()`.

## Required invariant

The live consumer must accept the exact canonical
`FutureRemediationEvidenceBundle` emitted by the producer and reject
producer-impossible subclasses before comparing them with the live rebuild.

A subtype may override equality/inequality. Broad `isinstance(...)` admission
therefore lets caller-defined comparison behavior participate in the integrity
decision. The canonical validator should instead fail closed on a non-exact
bundle object.

The regression includes:

- an exact canonical producer bundle as the green control;
- an equality-spoofing subclass carrying otherwise canonical fields;
- the same subclass carrying `execution_allowed=true`;
- caller-object preservation on rejection;
- no mutation of durable `runs`, `capability_leases`, or `evidence` rows.

The current validator returns a canonical rebuilt bundle after comparison, so
this finding is an integrity/fail-closed boundary issue rather than an execution
or remediation-authority bypass.

## Non-overlap

- #60 retains producer/live-validator production ownership.
- #194 retains persisted handoff/parser ownership.
- #404 owns direct-construction structural invariants for the typed dataclasses.
- This slice does not change persisted parsing, authoring requests, scope
  authorization, target-capable code, remediation/retest execution, deployment,
  verdicts, or attack-path state.

## Safety

Tests are deterministic and in-process. No model/network call, target
interaction, evidence collection, scanning, tool execution, remediation/retest
execution, deployment, future-state resolution, verdict creation, or attack-path
mutation is introduced.
