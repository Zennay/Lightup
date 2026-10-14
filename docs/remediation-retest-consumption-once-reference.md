# Retest receipt exactly-once consumption: offline reference contract

Status: **proposed reference only; not production authorization, attestation or a release gate**.

## Problem
A remediation/retest proof can be internally consistent yet replayed to drive multiple finding-status transitions. Evidence shape, content digest and chronological ordering alone do not establish single-use semantics.

## Proposed acceptance boundary
A production transition should bind an independently authenticated tenant, finding and revision to a trusted-issuer receipt, stable decision identifier and canonical SHA-256 proof digest. An atomic, durable, tenant-scoped ledger must reject repeated decision IDs or proof digests, even when submitted against a different finding within that tenant. Denial must be side-effect free; successful consumption and finding-state transition must commit together or roll back together. The reference accepts only typed, exact-context, canonical-format values, before recording consumption.

## Required production owner checks
1. Resolve tenant and finding from authenticated server-side state, never from untrusted request claims alone.
2. Verify proof byte digest, provenance, trusted signer/issuer, retention policy and revocation; a caller-provided hex string does not establish these.
3. Enforce the scope/authorization policy for the operation and the live revision at the moment of transition.
4. Use transactional uniqueness constraints for `(tenant_id, decision_id)` and `(tenant_id, proof_digest)`, with atomic finding transition; protect concurrent workers and retries across restarts.
5. Make duplicate submission outcome explicit (denial or idempotent read-only display); never issue a second mutation or duplicate audit success.
6. Test crash recovery, competing concurrent requests, durable storage, tenancy, privacy/retention and exact-head CI plus canonical permanent VPS before integration.
7. Coordinate with source owners of retest proof binding (#1077), evidence receipt binding (#1076), evidence chronology (#1066) and production workflow. Their files must not be overwritten.

## Offline coverage
`python -m unittest discover -s tests -p 'test_remediation_retest_consumption_once_reference.py' -v`

The synthetic in-memory reference exercises initial conditional acceptance; replay; decision-ID reuse; digest reuse across findings; tenant separation; context/revision mismatch; malformed types, identifier/digest boundaries, side-effect-free denial and immutable inputs. It is intentionally **not crash-safe, concurrent, persistent, cryptographically authenticated or an authorization grant**.

No actual targets, network calls, scans, remediation execution, status updates or deployments are authorized by this contract.
