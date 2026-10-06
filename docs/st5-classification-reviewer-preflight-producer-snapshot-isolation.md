# ST5 classification-reviewer preflight producer snapshot isolation

Issue #335 adds a producer-only serialization/snapshot invariant above exact #322 head `899ab25950d9656ed11fc1dcd6fa3d9c98f9ffb2`.

## Boundary

The active #326 worker owns the strict persisted handoff for `FutureSecurityClassificationReviewerPreflight`. This package therefore does **not** add, modify, or claim any persisted parser/reload behavior. It only proves properties of the already-existing #322 typed producer artifact and its public `as_dict()` / `to_json()` snapshots.

The package adds no production source.

## Invariant

For a real producer artifact created through the complete strict/live classification-review-request lineage:

- repeated `to_json()` is byte-for-byte deterministic;
- repeated `as_dict()` calls produce equal but independent top-level snapshots;
- candidate evidence/capability collections exported by `as_dict()` remain tuple-backed snapshots;
- replacing snapshot identity, lineage, reviewer, eligibility, classification, authority, future-state or verdict fields cannot mutate the typed preflight or its later JSON;
- JSON-decoded snapshots have independent mutable candidate-ID lists; mutating those caller-owned lists cannot change the typed tuple-backed preflight or another decoded snapshot;
- swapping/replacing reviewer and sufficiency-verifier identities in a snapshot cannot rewrite the canonical reviewer-independence fact.

## Stop line

The typed producer remains an eligibility/preflight artifact only:

- `independent_reviewer_verified=true`;
- `eligible_for_classification_review=true`;
- no classification decision or selected classification;
- no transition resolution;
- no collection, tool, target, execution, remediation/retest, deployment, or attack-path authority;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

## Safety and collision boundary

Only this document and a dedicated regression module are added. #322 producer source/tests, active #326 handoff work, #332/#334 consumer-integrity work, StateStore, durable consumer-gate files and scope-authorization work remain untouched.

All proof is in-memory. No model invocation, evidence collection, target interaction, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
