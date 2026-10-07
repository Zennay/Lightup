# Persisted authorization-grant tenant-lineage read contract

Issue: #829

## Purpose

A durable authorization grant stores both `client_id` and `engagement_id`.
The engagement is the durable tenant ownership lineage. Engagement authorization
alone must not make a grant row trustworthy when its duplicated client identity
disagrees with that lineage.

## Required contract

For `DomainStore.list_authorization_grants(ctx, engagement_id)`:

1. the caller must still be authorized to read the engagement;
2. each returned grant must have `grant.client_id == engagement.client_id`;
3. a cross-tenant-incoherent persisted row is filtered/fails closed before an
   `AuthorizationGrant` leaves the read boundary;
4. filtering is read-only and does not repair the row.

`get_current_grant()` composes `list_authorization_grants()` and therefore must
not surface an incoherent row as current authority.

Canonical persisted grant rows remain readable and current under the existing
validity semantics.

## Non-overlap

This acceptance slice is distinct from:

- #475 persisted approval/reference provenance at execution revalidation;
- #552/#554 execution-time durable client/engagement ownership;
- #652 issuance-time engagement identity;
- #743 direct in-memory grant lineage identity types;
- #827 finding tenant-lineage reads.

This branch changes tests/docs only. It does not modify domain production source,
grant issuance, execution policy/resolution, activation, orchestration,
evidence-remediation, target-capable code, deployment, verdicts or attack paths.

## Expected RED on current main

Current `list_authorization_grants()` authorizes the engagement and then runs:

`SELECT * FROM authorization_grants WHERE engagement_id=?`

It does not compare the selected row's persisted `client_id` with the owning
engagement's `client_id`. Therefore the two corruption cases are expected RED:

- list returns the cross-tenant-incoherent grant;
- `get_current_grant()` can return the same row as current.

## Safety

Temporary SQLite corruption proof only. No DNS/network I/O, target interaction,
scanning, model/tool execution, remediation/retest execution, deployment, verdict
creation or attack-path mutation.
