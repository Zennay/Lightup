# ST5 remediation/retest canonical item-order acceptance

Issue #385 protects the deterministic item sequence inherited by the ST5
remediation/retest plan from validated upstream ST3/ST4 lineage.

## Contract

Transition proposals require canonical item ordering by
`(change_node_id, subject_node_id)`. The graph-diff preview, security-delta
report and remediation/retest plan preserve that validated sequence.

A strict persisted handoff must therefore reject, not normalize, a reordered
item list. Recomputing the public plan digest after reordering must not make a
non-producer sequence acceptable.

## Acceptance

A canonical two-item payload with distinct item identities is accepted as the
positive control. Reversing only the item sequence and recomputing
`plan_sha256` must fail closed.

This is distinct from #378, which owns independent uniqueness and cross-item
current-path collision invariants rather than item sequence.

## Parallel boundary

Tests/docs only in draft #382. Active #190 source remains untouched.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
