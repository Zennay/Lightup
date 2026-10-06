# Evidence-sufficiency verifier-preflight snapshot isolation

Issue: #310

## Purpose

The ST5 evidence-sufficiency verifier preflight records only that one explicit operator identity is eligible to perform a later independent sufficiency review. It does not create a sufficiency decision, evaluate the evidence, select a classification, create a transition resolution, or grant execution authority.

Its public serialization surfaces therefore have to behave as detached snapshots. Caller mutation must never alter the canonical preflight or later persistence output.

## Invariants

The dedicated regression module proves that:

- repeated `to_json()` calls are byte-for-byte deterministic;
- untouched JSON round-trips through the strict #89 parser to the exact typed preflight;
- mutating a returned `as_dict()` snapshot cannot mutate the source preflight or its later JSON;
- independently returned snapshots do not alias their candidate-evidence or candidate-capability tuple containers;
- JSON-decoded caller-owned evidence/capability lists are copied into immutable tuples during strict parsing;
- later mutation of those caller-owned lists cannot mutate the parsed preflight;
- the verifier role remains exactly `operator` and review eligibility remains true;
- sufficiency-decision/evaluation, classification, transition and all action-authority fields remain false;
- future semantics remain unresolved and the security verdict remains not evaluated;
- the candidate classification remains an existing evidence claim only.

## Stop line

`eligible_for_sufficiency_review=true` is verifier eligibility only. It does not imply that a review happened or that evidence is sufficient. Any operator attestation, classification review, transition resolution, remediation/retest action or deployment remains a separate downstream boundary.

## Collision boundary

This slice adds only:

- `tests/test_future_security_evidence_sufficiency_verifier_preflight_snapshot_isolation.py`;
- `docs/future-security-evidence-sufficiency-verifier-preflight-snapshot-isolation.md`.

It does not modify #87/#89 producer/handoff source or existing tests/docs, and it does not modify active #90/#93/#95 or later classification-review work.

## Safety

All proof is in-memory persistence/integrity testing. There is no verifier decision, evidence collection, target interaction, security classification selection, remediation/retest execution, deployment, or attack-path mutation.
