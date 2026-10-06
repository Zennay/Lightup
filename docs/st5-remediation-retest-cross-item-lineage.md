# ST5 remediation/retest cross-item lineage acceptance

Issue #378 records a tests/docs-only RED contract above exact draft PR #190
head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

## Upstream invariant

The ST4 security-delta producer independently rejects duplicate change
identities, duplicate resolution identities, and one current attack-path
identity claimed by different changes.

The strict remediation/retest persisted handoff currently tracks only the full
`(change_node_id, subject_node_id, resolution_id)` tuple. Two items can
therefore remain tuple-distinct while violating an upstream uniqueness
constraint.

## Required fail-closed behavior

A re-signed persisted plan must be rejected when:

- distinct item tuples reuse one `change_node_id`;
- distinct item tuples reuse one `resolution_id`;
- two different changes claim the same `current_attack_path_id`.

Every tampered fixture recomputes a matching `plan_sha256`, so stale-digest
rejection cannot satisfy this contract. The canonical producer payload must
continue to round-trip unchanged.

## Ownership boundary

This branch changes only this document and the dedicated #378 regression
module. It does not modify #190 source, #377 blank-lineage files, the proven
#371/#373/#374/#375 integrity files, or direct-construction owner #325.

The branch is RED acceptance evidence for the #190 source owner, not a
promotion candidate while that dependency remains active.

## Safety stop line

PLAN-LAB ONLY. No evidence collection, model invocation, target interaction,
tool execution, remediation/retest execution, deployment, verdict creation, or
attack-path mutation. The contract only narrows persisted lineage integrity.
