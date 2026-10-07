# ST5 revised-plan review-request snapshot isolation

## Scope

This tests/docs-only acceptance slice is a child of revised implementation-plan
independent review-request #517.

- exact parent head: `f8de987ad069a784751a9e38ce258f6a118cea11`
- acceptance issue: #548
- production/source changes: **0**

It is separate from #519 reserved strict handoff, #525 builder atomicity, #527
metadata type hardening, #533 required-check item typing, revised-plan #511
children, scope authorization, and target-capable code.

## Invariant

Public serialization of
`FutureRemediationImplementationPlanRevisionReviewRequest` must remain a
detached snapshot boundary around immutable review-only metadata.

The regression proves that:

- repeated `to_json()` output is byte-for-byte deterministic;
- separately returned `as_dict()` values are independent caller-owned
  mappings;
- canonical untouched dict reconstruction returns the exact typed request;
- mutating a caller snapshot cannot mutate the frozen source request or later
  serialization;
- forged snapshots cannot claim revised-plan acceptance, execution authority,
  resolved future semantics, or a security verdict;
- mutating the caller-owned dictionary after reconstruction cannot mutate the
  reconstructed request.

## Authority stop line

The artifact remains review-request metadata only. It does not accept the
revised plan and authorizes no code/config change, tool call, execution, target
interaction, remediation, retest, deployment, attack-path mutation,
future-state resolution, or security verdict.

## Safety

The existing fixture uses only the in-memory model provider. No target
interaction, scanning, tool/remediation/retest execution, deployment, verdict
creation, or attack-path mutation is introduced.
