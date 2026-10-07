# Persisted risk requester provenance contract

Issue: #796  
Source owner: draft PR #146 (`decide_risk_elevation`)  
Pinned source head: `33c67f8e8b17bd9214c29d02fc52954cc42655da`

## Boundary

Risk-elevation self-approval is an authorization decision, so the durable identity
of the requester must remain canonical at decision time. The declared SQLite
TEXT affinity is not itself a runtime integrity guarantee: legacy or directly
corrupted rows can contain non-text values.

Before deciding a pending risk approval, persisted `requested_by` must therefore
be revalidated as an exact built-in, non-blank string. Invalid durable
provenance must fail closed before status or audit fields are mutated.

## Regression

`tests/test_scope_authorization_risk_requester_provenance.py` proves:

- a BLOB containing the reviewer's own UTF-8 identity cannot bypass the
  self-approval check through `bytes != str`;
- blank and whitespace-only requester provenance cannot be decided;
- rejected corruption leaves the approval PENDING with empty decision audit
  fields;
- canonical requester text still denies self-approval and permits an unrelated
  operator to approve.

This is durable requester-provenance validation only. #657 separately covers
runtime reviewer identity exactness, while #791 covers the caller-owned
`approval_id` binding identity.

## Ownership and safety

PR #146 retains all production ownership for serialized risk decisions. This
sidecar adds tests and documentation only.

No target interaction, DNS/network I/O, scanning, capability execution,
remediation/retest execution, deployment, verdict creation or attack-path
mutation is introduced.
