# ST5 implementation-plan live handoff input atomicity

This tests/docs-only invariant proves that the strict remediation
implementation-plan live handoff is a read-only validation boundary.

## Boundary

The contract covers
`load_and_validate_future_remediation_implementation_plan` after a persisted
implementation plan already exists. It is intentionally separate from:

- #358 dictionary-parser caller-input purity;
- nested duplicate-JSON integrity;
- implementation-plan snapshot isolation;
- downstream review/revision work;
- earlier remediation/retest-plan handoff atomicity.

No implementation-plan producer or handoff source is changed.

## Successful live validation

The regression uses the real implementation-plan producer fixture and treats
the complete typed live lineage as caller-owned:

- remediation authoring request;
- remediation evidence bundle;
- remediation/retest plan;
- security-delta report;
- graph-diff preview;
- transition proposal;
- transition resolution tuple;
- run-context tuple.

Before validation it records a deep value snapshot, recursive reachable
container identities, and the live `runs`, `capability_leases`, and
`evidence` rows.

Two consecutive validations must return the exact produced implementation plan
while all caller-owned typed values, identities, and ledger rows remain
unchanged.

During both calls, `StateStore.create_run`, `acquire_lease`, and
`add_evidence` are fail-fast sentinels. Any attempted public StateStore write
fails immediately rather than being hidden by a later rollback or compensating
write.

## Stale-lineage rejection

The regression also supplies a caller-owned remediation/retest plan with a
tampered plan digest while every other persisted and live input remains
canonical.

The complete handoff must reject that stale lineage twice with the same error.
The rejected typed input graph, recursive container identities, and live
StateStore rows must remain exactly unchanged, and no write sentinel may fire.

## Safety stop line

A successful validated implementation plan still means planning text only:

- `implementation_plan_created=true`;
- `code_change_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No model invocation, evidence collection, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
