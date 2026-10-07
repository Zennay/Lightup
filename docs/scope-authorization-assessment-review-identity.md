# Scope authorization: bind assessment review to one canonical request identity

Issue: #655  
Approval-decision invariant owner: #133  
Exact acceptance parent: draft #554 head `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

#133 established the fail-closed decision rules: approval is a real boolean and a persisted `DESTRUCTIVE_LAB_ONLY` client request must be denied even when legacy state contains it.

The remaining identity boundary is that `review_assessment_request()` receives `request_id` by annotation only and uses the caller object in multiple SQLite statements.

Today the sequence is effectively:

1. load `request_id`;
2. validate the loaded record's risk;
3. update rows matching `request_id`;
4. load `request_id` again.

SQLite permits caller objects to adapt themselves independently on every bind. One stateful object can therefore make step 1 read safe request A and step 3 update destructive request B.

## Contract

The decision boundary must require one exact built-in, non-blank request-ID string before the first persistence read.

That one canonical identity must bind:

- the record whose state/risk is checked;
- the row eligible for APPROVED/REJECTED mutation;
- the record returned after the decision.

Non-string SQLite-adaptable identities fail before adaptation and leave all assessment-request rows unchanged.

Canonical request A continues to approve normally. An exact legacy request B carrying `DESTRUCTIVE_LAB_ONLY` continues to fail #133's approval rule.

## Expected RED on the parent

The regression creates two requests and mutates request B in temporary SQLite to the producer-impossible destructive client risk that #133 protects against.

A stateful request-ID adapter then returns:

1. request A for the safety lookup;
2. request B for the update;
3. request B for the final lookup.

Current code can approve B because its destructive risk was never the record validated before the update. The acceptance contract instead rejects the identity object before its first SQLite adaptation.

## Independence

This does not replace #133. It pins the missing record-identity coherence needed for #133's safety check to protect the row that is actually mutated.

It does not alter request→grant binding (#177), risk-elevation decisions (#144), grant issuance, execution policy/orchestration, or target-capable behavior.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_assessment_review_identity.py`;
- `docs/scope-authorization-assessment-review-identity.md`.

There are **0 production/source changes**.

The proof uses temporary SQLite only. No DNS/network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation occurs.
