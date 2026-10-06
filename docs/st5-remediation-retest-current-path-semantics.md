# ST5 remediation/retest classification-dependent current-path acceptance

Issue #386 preserves the path-lineage semantics already enforced by ST4
transition resolution.

## Contract

Current attack-path lineage is not a generic optional list:

- `introduced` cannot reference an existing current attack path;
- `worsened`, `improved`, and `removed` require current attack-path
  lineage;
- `insufficient_evidence` is not given a new universal presence rule here.

The persisted handoff must reject impossible classification/path combinations
rather than accepting them after a caller recomputes the public plan digest.

## Acceptance

All five canonical producer classifications round-trip as the positive control.
The regression then:

- adds a valid-looking current path to an introduced item;
- removes all current paths from worsened, improved, and removed items;
- recomputes an exact matching `plan_sha256` after each mutation;
- requires strict persisted parsing to fail closed.

## Distinct ownership

This is separate from #383's universally required effect/evidence/capability
collections, #381's identifier/order canonicality, and #378's cross-item current
path collision contract. Tests/docs only in draft #382; active #190 source stays
untouched.

## Safety

Persistence-integrity only. No evidence collection, model invocation, target
interaction, tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
