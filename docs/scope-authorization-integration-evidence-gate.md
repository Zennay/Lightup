# Scope authorization integration evidence gate

Status: **review-only / fail closed**. This document is a handoff checklist, not an issued grant, executable authorization, or permission to test any asset.

## Why this exists
LightUp's parallel scope-authorization PRs contain independent offline reference predicates and regression fixtures. A passing isolated fixture does not prove that a production caller uses the predicate, that the caller has issuer-owned provenance, or that live dispatch revalidates permission. This checklist keeps integration evidence distinct from implementation claims.

## Merge and activation gates (all required)
1. **Ownership**: Identify the single production-source owner and record the reviewed exact base/head SHA. Do not cherry-pick from another active worker's branch without consent.
2. **Issuer provenance**: Verify grants originate in the authenticated, tenant-bound authorization register, never a report, plan, scanner, model answer, lab fixture, or client-asserted field.
3. **Complete binding**: Recheck tenant, requester, asset, allowed capabilities, purpose (current assessment / future simulation / lab evaluation), risk ceiling, test window, immutable request revision, issuer and independent human approver. Unknown fields and malformed types deny.
4. **Freshness**: Confirm revocation, expiry, consent withdrawal, risk changes, request updates, and policy changes invalidate previous allow decisions; do not reuse cached allow across mismatched revisions or identities.
5. **Dispatch time**: Prove the live executor independently re-resolves issuer-owned state and rejects revoked/expired grants immediately before dispatch. The UI, planning model, and cached preflight are not execution authority.
6. **Purpose isolation**: A future-state simulation or lab proof must never authorize active external targets. Purpose aliases, defaulting, or conversions must not imply consent.
7. **Safety**: No network/target calls, DNS lookups, scanning, exploits, elevated actions or live grant activation are required to evaluate these integration checkpoints.
8. **Evidence**: Attach exact-head Python 3.11 and 3.14 hosted unit-test results **and** exact-head canonical `[self-hosted, zcloud, vps]` run with hostname guard; record run IDs, conclusions, commit SHA and failures. Queued/cancelled/previous-head runs are not green proof.
9. **Review**: Require source-owner sign-off for integration and explicit human authorization for any real target. Passing CI by itself is insufficient.

## Evidence record template

| Field | Value |
| --- | --- |
| Production PR and owner | Not established |
| Integration base SHA | Not established |
| Integration head SHA | Not established |
| Hosted Python 3.11 run / conclusion | Not established |
| Hosted Python 3.14 run / conclusion | Not established |
| Canonical VPS run / hostname / conclusion | Not established |
| Issuer provenance test | Not established |
| Revocation-at-dispatch test | Not established |
| Purpose isolation test | Not established |
| Independent approver review | Not established |
| Target-active permission | **Disabled** |

**Gate decision:** DENY until every required evidence item has been reviewed and recorded for the exact code being activated.

## Non-overlap
This documentation does not modify or claim ownership of `src/lightup/*`, existing scope authorization references, active PR #107, source owners, deploy configuration, or target-capable paths. It is an integration artifact only. It intentionally cannot turn isolated test success into authorization.
