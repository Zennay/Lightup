# ST5 remediation/retest handoff action-classification acceptance

Issue #379 protects the persisted ST5 remediation/retest-plan boundary against a
semantic relabelling that cannot be produced by the live ST4 graph-diff preview.

## Canonical ST4 mapping

The upstream preview owns one fixed graph action for each verified transition
classification:

- `introduced -> add_path_hypothesis`
- `worsened -> modify_existing_path_risk_up`
- `improved -> modify_existing_path_risk_down`
- `removed -> remove_existing_path_candidate`
- `insufficient_evidence -> no_graph_change_claim`

The strict handoff must preserve that mapping independently of digest integrity.
A stored payload is not semantically valid merely because both enum strings are
individually recognized and `plan_sha256` was recomputed after tampering.

## Acceptance proof

The regression starts from canonical live-built plans, replaces only
`graph_diff_action` with a different valid enum value, and recomputes the exact
canonical plan digest. The strict persisted parser must reject every forged
classification/action pair. A companion round-trip assertion keeps all
canonical builder mappings accepted.

This isolates semantic validation from stale-digest validation: a digest mismatch
cannot satisfy the acceptance.

## Parallel boundary

This branch is a tests/docs-only child of exact PR #190 head
`c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`. It does not modify the active
#190 source files and does not take ownership of #377 or #378.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, security
verdict, or attack-path mutation is added.
