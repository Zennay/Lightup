# ST5 implementation-plan parse-to-live-validation chain atomicity

This tests/docs-only regression proves that the strict remediation
implementation-plan persisted entrypoint remains read-only when parsing and
full live-lineage validation are composed.

## Composition boundary

The sequence under proof is:

`caller-owned plan dictionary -> strict parse -> full live validation`

The isolated contracts remain independently owned:

- #358 proves dictionary-parser caller-input purity;
- #360 proves typed live handoff validation atomicity;
- nested-JSON integrity and snapshot-isolation remain separate siblings;
- this contract proves the real `load_and_validate...` entrypoint does not
  introduce an intermediate mutation or authority leak.

No parent source or existing parent tests are changed.

## Successful composed flow

A real implementation plan is serialized to a caller-owned dictionary. The
regression snapshots that payload together with the complete typed live lineage:
request, evidence bundle, remediation/retest plan, security-delta report,
preview, transition proposal, resolution tuple, and run-context tuple.

Before validation it records:

- deep caller-owned values;
- the persisted dictionary's byte-stable key/list ordering;
- recursive dict/list/tuple/set/frozenset identities;
- all live `runs`, `capability_leases`, and `evidence` rows.

The same caller-owned payload is loaded and live-validated twice. Both results
must equal the original produced implementation plan while every caller-owned
value, ordering snapshot, recursive container identity, and live ledger row
remains unchanged.

`StateStore.create_run`, `acquire_lease`, and `add_evidence` are fail-fast
sentinels during the composed calls.

## Rejection after successful parsing

The persisted implementation-plan dictionary remains canonical while the
caller supplies a remediation/retest live-lineage plan carrying a stale digest.

Strict parsing therefore succeeds before the deeper live lineage is rejected.
Repeated rejection must be deterministic and leave both the persisted payload
and every typed caller-owned input unchanged, with no StateStore write.

## Safety stop line

The composed boundary can return planning text only:

- `implementation_plan_created=true`;
- code/tool/execution/target/retest/deployment/attack-path authority remains
  false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No model invocation, evidence collection, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
