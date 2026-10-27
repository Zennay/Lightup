# Scope-authorization deny / unknown operational response (ST5)

Status: **non-executable operations guidance**, not a grant, implementation, release approval, or CI proof. This document covers the operator response when scope authorization cannot establish a current, exact, independently evidenced permission.

## Immediate invariant

**UNKNOWN = DENY.** No operator, retry loop, cached approval, prior run, assistant, or worker may reinterpret absent, stale, conflicting, corrupted, pending, revoked, expired, cross-engagement, or wrong-tenant authority as permission. Suspend the affected planned action before any target-capable handler, outgoing network request, evidence write asserting execution, or engagement RUNNING transition. Existing unrelated authorizations remain unchanged.

## Operator runbook

1. **Stop only the affected action.** Retain the task/request identifier, tenant and engagement identifiers, immutable plan reference, requested capability/risk and proposed asset as *references*; never copy session tokens, grant secrets, signed artifacts, cookies, or private credentials into diagnostics.
2. **Classify safely.** Choose one of: MISSING_AUTHORITY, INVALID_IDENTITY, SCOPE_MISMATCH, RISK_EXCEEDS_GRANT, EXPIRED_OR_NOT_YET_VALID, REVOKED, APPROVAL_UNVERIFIED, STORE_UNAVAILABLE, CLOCK_UNTRUSTED, AUDIT_UNAVAILABLE, or POLICY_CONFLICT. Unrecognized reasons map to UNKNOWN_DENIAL; never default to approved.
3. **Preserve evidence without minting authority.** Store a bounded, access-controlled denial record tied to tenant, engagement, immutable request identifier, revision, source component, timestamp and correlation identifier. The audit record must not contain raw tokens, request bodies, endpoint credentials or sensitive target payloads. If safe durable audit cannot be confirmed, do not proceed.
4. **Escalate to the authorized human owner.** Ask the operator to verify tenant, engagement, asset, capability, requested maximum risk, scope dates, the approval issuer and immutable approval provenance in the authoritative system. An operator acknowledgement is not itself an approval or an override.
5. **Restore through a new authoritative decision only.** A valid independent grant/reapproval must be issued through the established authorization workflow. Do not modify persisted grant rows, replay revoked identifiers, extend validity dates, broaden scope, or turn off checks as an incident workaround.
6. **Re-evaluate at the execution boundary.** Verify live, exact-typed authority again immediately before dispatch. An earlier green plan or test is not an executable permit. A successful re-evaluation applies to that single exact request context only.

## Incident / support handling

- A single malformed request: return generic denial to the caller, privately log a bounded reason and route it to request correction.
- Repeated cross-tenant, revoked, or provenance mismatch: stop related processing, preserve minimal correlation evidence and route to security review; **do not** try the same request under another tenant.
- Clock, database, revocation ledger or audit failures: stop affected active operations until trust is restored, independently verified and revalidated. Availability does not outrank authorization.
- Release-gate evaluation: mark as **NO-GO** until reproducible fail-closed integration regressions, exact-head hosted CI, canonical permanent VPS proof, source-owner review and explicit human release signoff exist. This document by itself proves none of those conditions.

## Offline review scenarios

| Condition | Expected outcome |
| --- | --- |
| Request has an expired approval but a historical green run | DENY; no historical replay |
| Revocation store is inaccessible while cached grant appears valid | DENY; no cache fallback |
| Requested asset differs by tenant or engagement | DENY; no identity fallback |
| Risk exceeds exact grant maximum | DENY; no automatic downgrade that silently changes requested action |
| Audit persistence unavailable | DENY; no unrecorded dispatch |
| Operator approves a support ticket but no canonical grant exists | DENY; support is not issuance |
| Canonical new grant arrives during a stopped request | NEW explicit evaluation; never resume with old decision |

## Boundaries and next integration

This is independent of active executor/source ownership (#107), live grant and assessment provenance branches, denial-observability acceptance (#1014), and release-evidence checklist (#1020). It changes no runtime code, policy, tests, handlers, scan capability or deployment. The source owner must review whether application error identifiers match these human-facing categories before adopting them. No live targets are used.