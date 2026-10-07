# Risk approval tenant-lineage read contract

Issue: #808

## Purpose

A persisted risk approval carries both `client_id` and `engagement_id`.
The engagement is the authoritative tenant-owned object, while the duplicated
`risk_approvals.client_id` column is not protected by a foreign key.

Client-scoped reads must therefore not treat the duplicated client field as
standalone authority. Otherwise durable drift can make an approval belonging to
client A's engagement visible to client B.

## Required contract

For client-scoped `DomainStore.list_risk_approvals()` reads:

- canonical approvals remain visible to the client that owns their engagement;
- unrelated clients see no canonical approval;
- an approval whose persisted `client_id` disagrees with the client owning its
  persisted `engagement_id` is not visible to the client named only by the
  drifted approval row;
- the read boundary is non-mutating; durable repair/audit handling is separate;
- operator repair visibility is deliberately left outside this acceptance slice.

The authoritative relationship is:

`risk_approvals.engagement_id -> engagements.engagement_id -> engagements.client_id`

The standalone `risk_approvals.client_id` value must agree with that lineage
before it can participate in tenant visibility.

## Acceptance proof

`tests/test_scope_authorization_risk_approval_tenant_lineage.py` provides:

- a green canonical owner/unrelated-client control;
- an expected-RED corruption case that rewrites only the duplicated approval
  `client_id` to another tenant while preserving the original engagement;
- a persistence assertion proving the read guard does not silently rewrite the
  corrupted row.

The branch is pinned to exact current-main commit
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

## Collision boundary

Tests and documentation only. No production source changes.

This does not modify active PR #146 risk-decision serialization or its sidecars
#807, #796, #791, #657, and #656. It also does not modify authorization-grant,
execution, activation, evidence-remediation, deployment, verdict, or attack-path
source.

## Safety

Tenant-isolation/read-integrity narrowing only. The proof models durable drift in
a temporary SQLite database. No DNS/network I/O, target interaction, scanning,
model/tool execution, remediation/retest execution, deployment, verdict
creation, or attack-path mutation.
