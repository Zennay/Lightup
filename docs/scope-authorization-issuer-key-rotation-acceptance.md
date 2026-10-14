# Scope authorization: issuer-key rotation acceptance contract (proposal)

Status: **offline design contract only**. Owner integration is required; this does not issue grants, activate targets, or attest production safety.

## Security boundary

A signature that verifies cryptographically is insufficient evidence that a scope grant may be executed. Admission **and each dispatch/retry** must bind an exact tenant, immutable grant revision, trusted issuer identity, issuer key identifier, signature algorithm, issue time, expiration and a current issuer trust-policy epoch. All claims require canonical serialization; no fallback to untrusted headers, user-supplied JWKS URLs, ambiguous key IDs, or algorithm negotiation.

An issuer-key rotation must never silently promote an old, unknown, withdrawn, cross-tenant or future key into authorization. Trust roots and rotation policy are administrator-controlled, not supplied in customer documents or AI output.

## Fail-closed acceptance matrix

| Scenario | Required result |
| --- | --- |
| Known current issuer and active signing key, exact tenant/scope/risk, fresh approval | Conditionally eligible; all other execution gates still apply |
| Unknown issuer or key ID, missing key ID or duplicate key identifier | Deny without dispatch |
| Retired key after effective withdrawal, including an otherwise valid historical signature | Deny new admission/retry/dispatch |
| Rotation between queue admission and dispatch | Revalidate live trust epoch; deny stale queued authorization |
| Algorithm confusion (e.g. unsigned, symmetric/asymmetric substitution), unsupported algorithm | Deny; never infer algorithm from untrusted token |
| Cross-tenant key reuse or tenant mismatch | Deny; no implicit global tenant wildcard |
| Key valid only in future or grant issued outside the key-validity window | Deny |
| Malformed or duplicated signed claim, Unicode/encoding ambiguity, noncanonical serialization | Deny without normalization-based widening |
| Revoked issuer or trust-store lookup error/time-out | Deny; audit sanitized reason |
| Concurrent key rotation and retried multi-step job | Recheck before every step; cancellation/denial on narrowed trust |
| Audit trail persistence failure at a denial boundary | No capability dispatch; surface an operational failure |

## Required proof before promotion

1. Production owner defines a durable administrator-authored trust-policy epoch and explicit issuer/key life cycle. State clearly whether historical signatures remain verifiable for read-only evidence while no longer permitting execution.
2. Verify cryptography, claims canonicalization, tenant binding, key time windows, approval lineage, grant revocation and scope/risk independently; a passing signature never bypasses any downstream guard.
3. Add offline deterministic clock, key-store and concurrency fixtures for every denial row; separately test positive continuity with a real *test* key pair only, without network access or targets.
4. Record exact pinned production commit, review, hosted CI and permanent VPS test results before calling the implementation ready. Fixture and documentation passes do **not** prove real executor safety.
5. Preserve non-conflicting ownership: ToolExecutor implementation #107; revocation #983/#989; human approval #992; release receipts #982. This proposal must be integrated or rejected by those owners rather than independently wiring an executor.

Non-goals: no real certificates, secrets, external key fetches, target interactions, scanning, executable tools, or permission expansion.
