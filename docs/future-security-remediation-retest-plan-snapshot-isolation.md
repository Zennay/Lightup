# ST5 remediation/retest plan snapshot isolation

Issue: #320  
Parent contract: draft PR #190  
Exact parent head: `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

This regression slice proves that the existing ST5 remediation/retest plan serialization boundary is not only structurally strict, but also snapshot-isolated across its public producer and persisted JSON representations.

## Proven boundary

The dedicated regression suite proves:

- repeated `FutureSecurityRemediationRetestPlan.to_json()` calls are byte-for-byte deterministic and canonical;
- canonical JSON and JSON-decoded dictionary forms round-trip to the exact typed plan through the strict #190 handoff;
- `as_dict()` returns detached top-level and nested item snapshots, so caller mutation cannot alter the source plan or later JSON;
- independently returned producer snapshots do not alias nested item dictionaries;
- the strict persisted parser copies caller-owned JSON lists into tuple-backed typed state;
- later mutation of caller-owned item lists, lineage collections, or the top-level payload cannot alter the parsed plan;
- attempts to forge execution, deployment, attack-path mutation, completion, future semantics, or security verdict fail closed;
- item action/requirement semantics remain derived from the typed classification and cannot be widened by snapshot mutation;
- an insufficient-evidence plan cannot be relabelled into remediation/retest readiness.

## Representation boundary

The producer-native `as_dict()` representation retains tuple-backed containers because it is produced from immutable dataclasses. The persisted #190 handoff intentionally accepts JSON-shaped lists and reconstructs immutable tuples.

This child does **not** widen the parser to accept producer-native tuples directly. It tests the canonical persisted boundary as:

`plan.to_json() -> json.loads(...) -> strict parser -> immutable typed plan`.

## Safety stop line

This work adds tests and documentation only. It does not add or authorize:

- evidence collection;
- model invocation;
- target interaction;
- tool or command execution;
- remediation execution;
- future-state retest execution;
- deployment;
- future-state resolution;
- security-verdict creation;
- attack-path mutation.

All execution/deployment/mutation flags remain false and future semantics remain unresolved with security verdict `not_evaluated`.

## Collision boundary

Only these files belong to #320:

- `tests/test_future_security_remediation_retest_plan_snapshot_isolation.py`
- `docs/future-security-remediation-retest-plan-snapshot-isolation.md`

No #190 source/test/doc file is modified, and no #318/#319 evidence snapshot sibling, remediation authoring/text/review branch, implementation-planning branch, or scope-authorization branch is touched.
