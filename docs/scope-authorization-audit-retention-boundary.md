# Scope authorization: audit retention and access boundary (offline proposal)

Status: **reference acceptance contract only**. This document and its fixture are not a deployed audit-log access-control mechanism, a retention schedule, or evidence that production authorization passes.

## Non-negotiable boundaries

1. Audit events about a customer's grant, human approval, revocation, denial, or scope/risk adjustment belong to the owning tenant. Tenant identity must come from trusted session/grant lineage, not from caller-selected labels, report filters, or serialized request data.
2. Read and export must each recheck the live access context. Cross-tenant requests deny even when a caller claims operator status. Public links, background exports, and caches must not bypass that check.
3. The fixture uses a deliberately narrow **reference** operator-export policy. It does not grant permissions to real roles or override existing application RBAC.
4. Revocation and failed checks remain auditable. Deleting/expiring records must not silently erase the only evidence needed to reconstruct a scope decision. Legal retention schedules, data minimization, privacy rights, encryption, and restricted erasure require separate human policy decisions.
5. Never include raw secrets, credentials, unrestricted target content, or reusable approval tokens in routine audit exports. Redaction must occur before durable export and cannot rely on UI hiding fields.
6. Reject unknown action, missing tenant, untrusted identity, and malformed role values **before** fetching, reading, exporting, or deleting any record.
7. Records should preserve immutable provenance (issuer, grant/revision, event time, event type and evidence reference) while minimizing personal data. Do not treat hash-like identifiers as proof of issuer authenticity.

## Identity/type confusion invariant

The reference rejects non-exact `str` tenant, role and action values before equality or membership checks. This is important because a Python `str` subclass may override equality and impersonate a recognized role, tenant or action. Tests cover forged action and role strings; the fixture contract does **not** attest to production caller validation.

## Offline acceptance pack

`tests/fixtures/scope_audit_retention_boundary.json` describes eight example decision cases, exercised by `tests/test_scope_audit_retention_boundary_contract.py`. The reference function is intentionally isolated from the application. Neither it nor the fixture proves actual tenant isolation, runtime revocation, export redaction or compliant retention.

## Production owner handoff

Before integration, the owning implementation must demonstrate: actual server-derived tenant resolution; independent authorization on every read/export; denial for stale/revoked sessions; separate privacy and retention approvals; atomic durable audit append where required; and exact-head hosted and permanent VPS verification. No target interaction or activation is authorized by this contract.
