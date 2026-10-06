# ST5 implementation-plan snapshot-isolation contract

Issue: #270

This tests/docs-only child sits above the strict implementation-plan handoff tracked by #237. It does not modify the implementation-plan producer or handoff source.

## Invariant

A `FutureRemediationImplementationPlan` is bounded planning metadata. Its public serialization helpers must never become a mutable backdoor into the canonical plan or its non-executable stop line.

The regression contract proves:

- repeated `to_json()` output is byte-for-byte deterministic and uses canonical compact/sorted JSON;
- top-level `as_dict()` mutation cannot change the source plan's lifecycle, future semantics, security verdict, summary, or any action-authority flag;
- nested plan-item dictionaries returned by `as_dict()` are detached copies;
- a forged snapshot reserialized to JSON is rejected for every action-authority widening;
- future-semantics and security-verdict widening fail closed;
- unexpected executable-looking nested keys such as `tool_arguments` fail the exact plan-item schema;
- independent snapshots do not alias each other;
- the untouched canonical JSON and untouched independent snapshot still parse to the exact source plan.

## Collision and safety boundary

Parent: exact #237 branch head `f8da50cae174d372be20ccef4a203a766db63618`.

Branch: `chatgpt/st5-implementation-plan-snapshot-isolation-20261006`.

Only this dedicated regression module and document are added. No #235/#237 production source, remediation-text #265/#266/#269 files, scope-authorization code, target interaction, model invocation, scanning, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation is introduced.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
