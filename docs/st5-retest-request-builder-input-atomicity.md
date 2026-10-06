# ST5 isolated retest-request builder input atomicity

This tests/docs-only child of the exact PR #52 retest-request producer proves
that `build_future_security_retest_request` is a read-only planning boundary.

## Scope

The proof is deliberately separate from upstream remediation/retest-plan
atomicity and persisted-handoff work. It changes no producer source and does not
touch retest authorization, tool-selection, scope, execution or target-capable
code.

## Successful request construction

The regression exercises all four classifications that can produce a
future-state retest request:

- `introduced`;
- `worsened`;
- `improved`;
- `removed`.

Before request construction it snapshots:

- the remediation/retest plan, security delta report, graph preview, transition
  proposal, resolution tuple and `RunContext` tuple by value;
- every nested tuple/list/dict/set/frozenset identity reachable from those
  caller-owned typed inputs;
- all persisted `runs`, `capability_leases` and `evidence` rows in the live
  `StateStore`.

During both repeated request builds, `StateStore.create_run`,
`StateStore.acquire_lease` and `StateStore.add_evidence` are fail-fast
sentinels. Any hidden write through those public mutation paths therefore fails
the regression immediately.

Both builds must return equal requests while every input/state snapshot remains
unchanged.

## Rejection atomicity

Two fail-closed paths receive the same treatment:

1. an `insufficient_evidence` plan is rejected repeatedly before it can become
   a retest request;
2. a canonical-shape plan with a stale `plan_sha256` is rejected after the
   normal live remediation/retest-plan rebuild.

Both rejection paths must preserve caller-owned values, nested container
identities, live ledger rows and the untouched write sentinels.

## Safety boundary

The resulting request remains planning-only:

- `isolated_future_state_required=true`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No target interaction, evidence collection, tool invocation, remediation or
retest execution, deployment, verdict creation or attack-path mutation is
introduced by this proof.
