# ST5 remediation/retest blank-lineage persisted-handoff acceptance

Issue #377 records a tests/docs-only RED contract above exact draft PR #190
head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`.

## Gap under test

The strict persisted handoff currently rejects empty strings but treats
whitespace-only strings as non-empty. Because the public plan digest covers
these fields, a tampered payload can be re-signed with its new blank identity
and reach typed plan construction unless the identity boundary itself rejects
canonical blanks.

The regression deliberately recomputes a matching `plan_sha256` after every
mutation. A stale-digest rejection therefore cannot satisfy this contract.

## Required fail-closed identities

Whitespace-only values must be rejected for top-level lineage identities:

- `client_id`
- `current_twin_id`
- `twin_id`
- `changeset_id`

The same rule applies to nested plan-item identities:

- `change_node_id`
- `subject_node_id`
- `resolution_id`

And to entries in persisted lineage collections:

- `current_attack_path_ids`
- `effect_ids`
- `evidence_ids`
- `capability_ids`

Canonical producer payloads must continue to round-trip unchanged. The handoff
must fail closed rather than trim or normalize persisted identity text.

## Ownership boundary

This branch changes only this document and the dedicated #377 regression
module. It does not modify #190 production source, the direct-construction owner
from #325, or the #371/#373/#374/#375 integrity files.

The branch is intentionally RED acceptance evidence, not a promotion candidate,
until the #190 source owner absorbs or otherwise resolves the invariant.

## Safety stop line

This contract is PLAN-LAB ONLY. It performs no evidence collection, model
invocation, target interaction, tool execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation. Existing authority flags
remain false and future semantics remain unresolved.
