# Risk decision pending-audit coherence

Issue: #807

## Purpose

A risk-elevation decision is only safely one-shot when durable status and durable
decision-audit fields agree. A row that still says `pending` but already carries
`decided_by` or `decided_at` is internally inconsistent and must not be used
as the source for a fresh authorization decision.

PR #146 serializes the decision transaction and protects the status transition,
but its exact source head currently trusts `status=pending` without validating
that the audit fields are empty. A legacy or corrupted row can therefore have
pre-existing audit evidence overwritten by a later decision.

## Required contract

Before mutating a persisted pending risk approval,
`DomainStore.decide_risk_elevation()` must require both:

- `decided_by IS NULL`;
- `decided_at IS NULL`.

If either field is already populated, the row fails closed as inconsistent
durable state. Rejection must happen before the UPDATE and must preserve
`status`, `decided_by`, and `decided_at` unchanged.

An untouched canonical pending row remains decidable by an unrelated operator.
Existing self-approval, destructive-risk, decision-bool, and serialized
one-shot checks remain separate invariants.

## Acceptance proof

`tests/test_scope_authorization_risk_decision_audit_coherence.py` provides:

- a green control for an untouched pending approval;
- an expected-RED case with only `decided_by` pre-populated;
- an expected-RED case with only `decided_at` pre-populated;
- an expected-RED case with both audit fields pre-populated;
- preservation checks proving a rejected inconsistent row is not rewritten.

The branch is pinned directly to PR #146 exact head
`33c67f8e8b17bd9214c29d02fc52954cc42655da`.

## Collision boundary

This slice adds tests and documentation only. It does not modify
`src/lightup/domain.py` or any other production source.

PR #146 retains production ownership of `decide_risk_elevation`. #791 owns
caller-supplied approval identity, #796 owns persisted requester provenance,
#657 owns runtime reviewer identity, and #656 owns risk-elevation justification
intake.

## Safety

Authorization audit-integrity narrowing only. The proof mutates a temporary
SQLite database to model legacy/corrupted durable state. It performs no
DNS/network I/O, target interaction, scanning, model/tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
