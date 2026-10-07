# Finding tenant-lineage read contract

Issue: #827

## Purpose

A persisted finding carries both a duplicated `client_id` and an `engagement_id`.
The engagement is the durable ownership lineage. Client-visible reads must not trust
the duplicated client field by itself.

## Invariant

For every client-scoped finding read:

1. the finding's persisted `engagement_id` must resolve to an engagement owned by
   the scoped client;
2. the finding's persisted `client_id` must equal that same client;
3. a mismatch is filtered fail-closed without rewriting durable state;
4. canonical rows remain visible to their owner and hidden from unrelated clients.

The same coherence rule applies when a client reads one explicitly authorized
engagement. Authorization to the engagement does not make an internally
cross-tenant finding row trustworthy.

## Operator audit behavior

An operator-wide read with no client filter remains intentionally unchanged. That
view may expose an incoherent legacy row so an operator can diagnose or repair it.
When an operator supplies an explicit client filter, that read is tenant-scoped and
must enforce the same finding/engagement lineage coherence as a client context.

## Non-goals

This change does not alter:

- finding creation or retest mutation;
- risk-approval state or decision logic;
- authorization-grant issuance or execution;
- evidence-remediation flows;
- target interaction, scanning, deployment, verdicts, or attack-path state.

## Regression proof

`tests/test_scope_authorization_finding_tenant_lineage.py` covers:

- canonical owner/unrelated-client controls;
- a corrupted row whose duplicate `client_id` is changed to another tenant;
- generic client listing;
- explicit engagement-scoped listing;
- operator reads with an explicit client filter;
- durable-state immutability on rejection;
- unchanged unfiltered operator-wide audit visibility.
