# Independent scope approval reviewer — offline acceptance contract

Status: proposed M7/ST5 acceptance contract, **not** an implementation or authority grant.

## Separation of duties

An active-target authorization request must have a requestor identity and a verified
human approver identity bound to the same tenant, engagement, immutable request
revision, requested asset set, capability set, risk ceiling, and validity window.
A requestor must not approve their own request, including via another account
mapped to the same verified human principal. The service must reject anonymous,
service-account, unverified, missing, or ambiguous approver identities.

The approval must be an explicit affirmative decision made after the request
revision was finalized; a view, edit, notification, or absence of a rejection is
not approval. Approval for revision N is invalid after any material change to
scope, exclusions, capabilities, tenant, engagement, risk, or validity period.
Reapproval requires a new explicit review and must not inherit an older signature.

The reviewer must be independently permitted for the tenant and action at
decision time; possessing administrator UI access alone is insufficient proof.
Approval evidence must preserve the verified human principal, role/permission
snapshot, reviewed revision digest, decision timestamp (timezone-aware UTC),
and a stable audit correlation identifier, without exposing access tokens.
Two nominal accounts of the same human do not satisfy independent review.

## Fail-closed acceptance cases

| Case | Expected |
| --- | --- |
| Same verified person requests and approves | DENY |
| Different accounts but same verified principal | DENY |
| Approver principal absent or unverified | DENY |
| Approval predates reviewed revision | DENY |
| Request revision changed after approval | DENY |
| Tenant or engagement differs between decision and request | DENY |
| Scope or risk expands after approval | DENY |
| Reviewer lacks tenant approval permission | DENY |
| Approval explicitly rejected or revoked | DENY |
| Approval record malformed, ambiguous or unverifiable | DENY |
| Distinct verified approver, exact revision, scoped approval | CONDITIONALLY ELIGIBLE, subject to every other activation gate |

## Integration and evidence

PR #107 owns executor authorization logic; this document does not modify or
replace it. The owner must connect the approval proof to a **trusted immutable
issuer-backed** lineage, not to caller-controlled strings or dataclass equality.
Revalidate at dispatch and relevant subsequent steps, including revocation and
reapproval. Existing revocation PRs #983/#989 and provenance fixture PR #992
remain independent; coordinate before composing overlapping contracts.

Required verification: tests against the actual integration, exact-head hosted
and permanent VPS runner receipts, source-owner review, negative tenant replay
and same-human alias regressions. A documentation-only PR is never proof that
execution is safe, and approval alone must never start active capabilities.
No network, targets, scans, credentials or deploys are exercised here.
