# ST5 evidence sufficiency review request

This package is the handoff after a candidate evidence set has passed both:

1. freshness admission; and
2. read-only transition-metadata contract review.

It does **not** decide that evidence is sufficient. It creates the exact bounded
request an independent evidence verifier must review next.

## Preconditions

`build_future_security_evidence_sufficiency_review_request(...)` first calls
`validate_future_security_evidence_metadata_contract_review(...)`.

That live validator recursively revalidates the freshness admission,
freshness constraints, evidence collection request, upstream ST4/ST5 lineage,
candidate lab RunContext and current `StateStore`. A stale serialized review
therefore cannot become a new sufficiency request.

## What is preserved

The immutable request binds:

- client and current/future twin lineage;
- ChangeSet;
- evidence collection request SHA-256;
- freshness constraints SHA-256;
- freshness admission SHA-256;
- metadata-contract review SHA-256;
- source resolution, change and subject identities;
- candidate run, evidence and capability identities;
- the candidate `classification` value only as an **untrusted evidence claim**.

Raw evidence metadata, source, payload, target details, arguments and
credentials are not copied into the request.

## Required independent checks

The canonical `required_checks` are:

- `classification_justification`;
- `evidence_sufficiency`.

The request sets both `independent_verifier_required=true` and
`review_required=true`.

Those flags are obligations, not approval signals.

## Fail-closed semantics

Even a valid request retains:

- `metadata_contract_verified=true`;
- `freshness_check_passed=true`;
- `evidence_sufficiency_evaluated=false`;
- `classification_selected=false`;
- `transition_resolution_created=false`;
- `collection_authorized=false`;
- `tool_call_created=false`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `remediation_authoring_allowed=false`;
- `future_state_retest_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

A candidate metadata claim therefore cannot become a LightUp-selected
classification merely by reaching this stage.

## Persistence and drift

`sufficiency_request_sha256` deterministically binds the exact bounded
lineage, required checks and safety semantics.

Persisted requests must be passed through
`validate_future_security_evidence_sufficiency_review_request(...)` before
use. The validator rebuilds the request from the live metadata review and
requires exact equality, so review, evidence, capability or upstream lineage
drift fails closed.

Dependency for this stacked slice is draft PR #78 and its upstream
evidence-remediation chain. Exact-head hosted Python 3.11/3.14 and canonical
`vps-bb300bba` proof remain required after the parent lands.
