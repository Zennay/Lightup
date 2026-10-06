# ST5 direct remediation/retest plan construction

Issue: #325  
Parent contract: draft PR #190  
Exact parent head: `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

The strict #190 persisted handoff already rejects malformed or widened remediation/retest plans. This child closes the matching in-process boundary: callers can no longer bypass those stop-line invariants by directly instantiating the frozen producer dataclasses or by using `dataclasses.replace()`.

## Direct plan-item invariant

`FutureSecurityRemediationRetestPlanItem` now fails closed unless:

- change, subject and resolution identities are non-empty strings;
- `resolution_sha256` is canonical lowercase SHA-256;
- classification, graph-diff action and next action are actual enum members rather than raw strings;
- remediation/retest/evidence requirement fields are exact booleans;
- next action and requirement booleans exactly match the classification-derived planning semantics;
- current-path, effect, evidence and capability collections are tuples of unique non-empty strings.

## Direct top-level plan invariant

`FutureSecurityRemediationRetestPlan` now fails closed unless:

- schema version is exact and plan/twin/change identities are non-empty;
- lineage digests and `plan_sha256` are canonical lowercase SHA-256 values;
- versions and counts are non-negative exact integers, rejecting bool/int confusion;
- items are a non-empty tuple of exact validated plan-item values with unique identities;
- remediation, retest and evidence-gap counts equal the item-derived counts;
- insufficient-evidence state is derived from the actual item classifications and evidence requirements;
- `plan_complete` remains exact true;
- execution, deployment and attack-path mutation authority remain exact false;
- future semantics remain `unresolved`;
- security verdict remains `not_evaluated`;
- `plan_sha256` remains a canonical lowercase SHA-256 value.

A deliberately stale but syntactically canonical plan digest remains constructible. Open downstream consumers #52 and #60 intentionally create `dataclasses.replace(plan, plan_sha256="0"*64)` and prove live revalidation rejects that artifact. Digest **equality/recomputation** therefore remains at the established live-consumer boundary rather than being silently moved into this constructor.

## Safety

This is integrity narrowing only. It adds no evidence collection, model call, target interaction, tool execution, remediation execution, retest execution, deployment, future-state resolution, verdict creation or attack-path mutation.

## Collision boundary

The #325 branch changes only:

- `src/lightup/future_security_remediation_retest_plan.py`;
- `tests/test_future_security_remediation_retest_plan_direct_construction.py`;
- `docs/future-security-remediation-retest-plan-direct-construction.md`.

It does not modify the #190 handoff source/tests/docs, #320 snapshot files, #318/#319 evidence snapshot siblings, remediation authoring/text/review files, implementation-planning files or scope-authorization files.
