# ST5 implementation-plan revision-request snapshot isolation

## Scope

This is a tests/docs-only acceptance child of the strict implementation-plan
revision-request handoff in #501.

- exact parent head: `81cd78f074a777a0380672050082fd21616a447c`
- acceptance issue: #534
- production/source changes: **0**

It is intentionally separate from #506 parser input-purity, #507 live-validation
atomicity, #510/#516/#522 persisted type-hardening, #486 builder atomicity,
#528/#530 direct-construction type slices, revised-plan work, scope
authorization, and target-capable code.

## Invariant

Public serialization of
`FutureRemediationImplementationPlanRevisionRequest` must behave as a detached
snapshot boundary.

The regression proves that:

- repeated `to_json()` output is byte-for-byte deterministic;
- canonical untouched dict and JSON snapshots round-trip to the same typed
  request;
- separately returned `as_dict()` snapshots are independent caller-owned
  objects;
- replacing snapshot fields cannot mutate the frozen source request or change
  later serialization;
- forged snapshots that reorder revision checks, claim plan acceptance, widen
  action authority, resolve future semantics, or publish a security verdict
  fail closed at the strict parser;
- mutating the caller-owned dictionary after a successful parse cannot mutate
  the already parsed typed request.

## Authority stop line

Snapshot creation and parsing remain persistence/integrity operations only.
They do not create a revised plan and do not authorize code/config changes,
tool calls, execution, target interaction, remediation, retesting, deployment,
attack-path mutation, future-state resolution, or a security verdict.

## Safety

No model invocation, target interaction, scanning, tool/remediation/retest
execution, deployment, verdict creation, or attack-path mutation is introduced
by this acceptance slice.
