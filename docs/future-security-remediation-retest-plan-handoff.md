# ST5 remediation/retest plan serialization handoff

LightUp already builds an immutable, evidence-linked ST5 remediation/retest plan
from live-revalidated ST4 lineage. This handoff adds a strict boundary for
persisting or transporting that plan without silently trusting arbitrary JSON.

## Boundary

`future_security_remediation_retest_plan_from_json` rejects duplicate JSON keys
before normal decoding can collapse them. The typed parser then requires the
exact top-level and item schemas, strict primitive types, canonical lowercase
SHA-256 values, valid enums, unique item identities, exact remediation/retest/
evidence requirement semantics, internally consistent aggregate counts, fixed
fail-closed safety flags, and a recomputed `plan_sha256`.

This specifically prevents type-confusion such as `1` standing in for a
boolean, schema smuggling through unknown keys, last-value-wins duplicate JSON
keys, and persisted action flags that no longer match their ST4
classification.

## Trust model

Successful parsing proves only serialization integrity. It does **not** prove
that the source report, preview, transition resolutions, run contexts, or
StateStore evidence are still current.

Any consumer that uses a parsed plan for a later evidence/remediation workflow
must immediately call
`validate_future_security_remediation_retest_plan_handoff`. That validator
rebuilds the plan from the live lineage with
`build_future_security_remediation_retest_plan` and requires exact equality
before follow-up use.

## Safety invariants

The handoff cannot authorize target interaction or execution. Parsed plans must
retain:

- `execution_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`

It creates no collection request, tool call, remediation action, future-state
retest, deployment action, or attack-path mutation.

## Parallel ownership

This slice is intentionally isolated in new files. It does not modify the
active remediation-evidence bundle owned by PR #60 or the evidence-collection
dependency stack rooted at PR #62.
