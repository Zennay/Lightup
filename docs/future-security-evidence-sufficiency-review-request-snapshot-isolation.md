# Evidence-sufficiency review-request snapshot isolation

Issue: #309

## Purpose

The ST5 evidence-sufficiency review request is immutable planning and verifier-handoff metadata. It records that fresh, metadata-valid candidate evidence must receive an independent sufficiency review; it does not itself decide sufficiency, select a classification, create a transition resolution, or grant execution authority.

Its public serialization surfaces therefore have to behave as detached snapshots. Caller mutation must never alter the canonical typed request or later persistence output.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON round-trips through the strict #84 parser to the exact typed request;
- mutating a returned `as_dict()` snapshot cannot mutate the source request or its later JSON;
- independently returned snapshots do not alias their candidate-evidence, candidate-capability, or required-check tuple containers;
- JSON-decoded caller-owned lists for evidence IDs, capability IDs, and required checks are copied into immutable tuples during strict parsing;
- later mutation of those caller-owned lists cannot mutate the parsed request;
- review obligations cannot be turned off;
- sufficiency evaluation, classification selection, transition creation, collection/tool/target/execution/remediation/retest/deployment/attack-path authority cannot be forged on;
- future semantics remain unresolved and the security verdict remains not evaluated;
- the candidate classification remains an existing evidence claim only and cannot be replaced with an unsupported result.

## Stop line

A valid artifact may state only that metadata/freshness checks passed and independent review is required. It retains:

- `evidence_sufficiency_evaluated=false`;
- `classification_selected=false`;
- `transition_resolution_created=false`;
- all action-authority fields false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

Any sufficiency decision, classification review, transition resolution, remediation/retest action or deployment remains a separate downstream boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_sufficiency_review_request_snapshot_isolation.py`;
- `docs/future-security-evidence-sufficiency-review-request-snapshot-isolation.md`.

It does not modify #82/#83/#84 producer/handoff source or existing tests/docs, and it does not modify active #87/#89/#90/#93/#95 or later classification-review work.

## Safety

All proof is in-memory persistence/integrity testing. There is no evidence collection, model/verifier invocation, target interaction, security classification selection, remediation/retest execution, deployment, or attack-path mutation.
