# LightUp #1493 — Production-owner cross-grant runtime integration contract (proposal only)

**Authority:** NONE. **State:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.  
This document is a proposed review contract, **not** an approved implementation, source change, deployment, operator approval or executable design. No active target, handler or customer account is touched by #1493.

## 1. Existing independently owned source paths

| Existing shape | Existing policy consumer | Missing binding within this preview |
|---|---|---|
| `models.Authorization` on `Target` | `ScopePolicy.decide`, `ActivationGate.issue` | No authenticated tenant/engagement or durable immutable grant linkage |
| `engagements.AuthorizationGrant` on `ExecutionRequest` | `ExecutionPolicy.decide` | A caller-supplied grant shape, not proof of durable consent or revocation |
| `cross_grant_lineage_review_1493` (this branch) | **None**; deliberately unwired | All supplied actor/client/asset/clock fields can be fabricated |

Source owners #99/#100 and executor/permit owners must review this proposal before editing any runtime path. Coordinate with #1491/#1492 (legacy permit/decision snapshot), #262 (independent gate matrix), #737 (revocation), #639/#554 (persisted same-row scope), and the ingress/tenant identity owners. Their branches and production files are **not** modified by this work.

## 2. Proposed authoritative facts (all MUST be resolved server-side)

Before considering an active tool, source owners should obtain, **from one trusted immutable or versioned, authenticated transaction**, the same values for every step:

1. **Authenticated principal and operator**: bound to a trusted login/session identity and authorized operator role. Never trust `legacy.owner` or free-text `durable.approved_by` as authentication.
2. **Tenant and engagement**: canonical server-side `client_id`, `engagement_id`, membership and source-of-truth records. User-supplied tenant strings are untrusted hints only.
3. **Client consent and grant issuance**: durable proof identifier, immutable approval event, source material, issuer/approver identity, explicit asset inventory and capabilities, authorized risk ceiling, bounded window, and permitted retest policy. Approval **must not** be inferred from two matching strings or from a successful offline review.
4. **Grant version and revocation**: revocation/widening/narrowing events must be integrity protected and bound to the same grant version read for issuance. Deny absent/malformed/revoked/expired approval.
5. **Canonical requested operation**: target asset, resolved identity/address where applicable, exact capability ID, risk level, and approved data handling, all bound to the same trusted grant snapshot and tenant. No wildcard/coercion/case-folding/implicit private-lab elevation.
6. **Server-derived clock and use-time check**: a trusted operation-start instant **and immediate revalidation at tool dispatch**. A clock provided by the request or this offline CLI is not an authority source.
7. **Evidence binding**: append-only auditable decision ID and grant version, operation identity and explicit deny reason, without leaking customer secrets in error bodies.

## 3. Proposed canonical read/authorize/use choreography

Review suggestion for production owners, **not executable code**:

```text
authenticate request and server tenant/operator
  → canonicalize requested asset, capability, risk, operation
  → lock/read trusted same-version durable engagement + consent + grant + revocation
  → resolve legacy assertion only as metadata under that trusted join
  → validate exact identity, operation scope, risk, UTC validity and current revocation
  → bind decision token to tenant, actor, grant/version, asset, capability, risk and operation
  → BEFORE ANY dispatch: verify token, grant/version, revocation and allowed operation again
  → atomically reserve immutable evidence and operation identity
  → only with security-approved real implementation may a separately owned executor consume it
```

**TOCTOU veto:** If revocation or grant version changes between read and dispatch, HOLD/deny. If the safe atomicity model is not implementable or reviewed, do not issue a permit. A signed snapshot without online revocation validation does **not** satisfy use-time safety.

**Do not rewire** `ActivationGate`, `ExecutionPolicy`, `DomainStore`, executor or network tools from this branch. A coherent synthetic `REVIEW_ONLY` must never be converted into `allowed=True`.

## 4. Proposed acceptance matrix for source owner to implement later

| Scenario (all fixtures synthetic) | Required source-integrated outcome |
|---|---|
| Both independent source gates allow, but actors/references differ | DENY, no permit, no handler, auditable reason |
| Both source gates allow, but canonical tenant differs | DENY cross-tenant, no data disclosure |
| Same target/capability replayed under different durable grant IDs in one request | DENY ambiguous provenance |
| Same grant ID, different legacy window or durable scope/version | DENY stale/conflicting assertion |
| Original durable row has malformed assets/exclusions or capabilities | DENY on same fetched row, not on a reconstructed copy alone |
| Request uses alias, Unicode confusable, IPv6 zone ID, private/localhost auto-promotion | DENY unless explicitly reviewed and granted by canonical source owners |
| Valid approval becomes revoked after allow but before dispatch | DENY on use-time recheck and produce denial evidence |
| Concurrent revocation and attempted dispatch | Deny unless an audited linearizable transaction proves dispatch preceded revocation |
| Multiple scope-consistent distinct assets and capabilities, grant valid and independently authenticated | May be considered by real policy owner; **this preview only reports REVIEW_ONLY** |
| Offline CLI returns REVIEW_ONLY or exit 2 | Never authorizes, grants or dispatches anything |
| Host CI green but genuine registered VPS CI queued/absent | DRAFT/HOLD, never release |
| Full hosted suite still has ordinary #301 failure / integration skipped | DRAFT/HOLD; fix via existing #301 owner PR, do not disable tests |

## 5. Gates and unowned dependencies

- **Source-owner design review:** identify the canonical, authoritative join and current trusted issuance process; document tenant/actor provenance. Owners of runtime code must implement and validate actual wiring.
- **Revocation/use-time and concurrency review:** independently prove current-state check at dispatch and race failure behavior.
- **Security/privacy review:** customer-controlled scope only, no out-of-scope active operation, safe log redaction and credential separation.
- **Full exact-HEAD CI:** currently separately fails legacy historical date fixture #301; source-owner draft #1452 handles it. The fixture should be repaired *without masking an actual security failure* and producer integration must truly run.
- **Registered canonical VPS proof:** `self-hosted,zcloud,vps` must map to the intended `vps-bb300bba` with verifiable machine identity; operator issue #1144 owns connectivity/registration.
- **Explicit human GO:** only after all preceding evidence and consent exist. This document alone **never** grants approval.

## 6. Reviewer handoff checklist (must remain unchecked here)

- [ ] Real authenticated client/operator provenance established.
- [ ] Durable grant/source version and revocation incorporated into an atomic use-time gate.
- [ ] Correct canonical asset/capability/risk and tenant binding verified by original owners.
- [ ] Cross-grant collision and legacy-window replay source-integrated RED→PASS tests proven.
- [ ] No handler/scan/evidence side effect before trusted grant and use-time revalidation.
- [ ] Independent security/privacy assessment completed.
- [ ] Exact-head full hosted suite and producer integration genuinely PASS.
- [ ] Exact-head registered permanent VPS job proven, with correct machine identity.
- [ ] Authorized client consent and explicit human operator GO captured.
- [ ] Only then consider separately reviewed merge/deployment.

**Until then, keep #1494 DRAFT/HOLD.** This is a non-authorizing source-owner specification, not an instruction for other workers to bypass their scope or assume that an integration is ready.
