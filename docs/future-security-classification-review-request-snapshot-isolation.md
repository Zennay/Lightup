# Classification-review request snapshot isolation

Issue: #312

## Purpose

The ST5 classification-review request is eligibility metadata for a later independent classification review. It is created only after the operator attested that evidence is sufficient and the existing classification claim is justified, but it does not itself select a LightUp classification, create a transition resolution, or grant action authority.

Its public serialization surfaces therefore have to behave as detached snapshots. Caller mutation must never alter the canonical typed request or later persistence output.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON round-trips through the strict classification-review request parser to the exact typed request;
- mutating a returned `as_dict()` snapshot cannot mutate the source request or its later JSON;
- independently returned snapshots do not alias their candidate-evidence or candidate-capability tuple containers;
- JSON-decoded caller-owned evidence/capability lists are copied into immutable tuples during strict parsing;
- later mutation of those caller-owned lists cannot mutate the parsed request;
- evidence sufficiency, claim justification, sufficiency-decision/evaluation and classification-review eligibility/requested markers remain exact true;
- classification selection, transition creation and all collection/tool/target/execution/remediation/retest/deployment/attack-path authority remain false;
- future semantics remain unresolved and the security verdict remains not evaluated;
- the candidate classification remains an existing evidence claim only.

## Stop line

`classification_review_required=true` is a request for a later independent review only. It does not mean a classification has been selected or that the future Security Twin may be mutated.

## Collision boundary

This slice adds only:

- `tests/test_future_security_classification_review_request_snapshot_isolation.py`;
- `docs/future-security-classification-review-request-snapshot-isolation.md`.

It does not modify the active classification-review request producer/handoff/consumer source or existing tests/docs, and it does not modify sufficiency attestation/verifier-preflight snapshot siblings.

## Safety

All proof is in-memory persistence/integrity testing. There is no classification decision, transition resolution, evidence collection, target interaction, remediation/retest execution, deployment, or attack-path mutation.
