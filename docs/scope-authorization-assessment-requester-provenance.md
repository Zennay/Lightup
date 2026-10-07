# Persisted assessment requester provenance

Issue: #879

## Boundary

`assessment_requests.requested_by` is durable authorization/audit provenance. The canonical producer writes `AccessContext.user_id`, so the read boundary must not reinterpret producer-impossible SQLite values as valid requester identity.

This acceptance slice is pinned to `main` `1abc16a66fc490b1ba7272890dfbf498482fca9c` and intentionally changes no production source.

## Required contract

When `DomainStore._request_from_row()` reconstructs an assessment request:

- `requested_by` is accepted only when it is an exact built-in `str`;
- it must contain at least one non-whitespace character;
- BLOB-backed or blank requester provenance fails closed before an `AssessmentRequestRecord` escapes the read boundary;
- a rejected read never repairs, rewrites, deletes, or normalizes the durable row;
- canonical requester text continues to round-trip unchanged.

## Expected proof state

The canonical round-trip is GREEN on the pinned parent.

The BLOB and blank/whitespace corruption cases are intentionally RED until the domain read owner absorbs the fail-closed persisted-provenance guard.

## Collision boundary

This slice is tests/docs only. It does not modify request intake, mode/risk/assets typing, request-review identity or decision semantics, request-to-grant binding, grant issuance, execution policy, activation, evidence/remediation, deployment, verdicts, or attack-path state.

## Safety

Tests use only a temporary SQLite database and in-process domain calls. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation occurs.
