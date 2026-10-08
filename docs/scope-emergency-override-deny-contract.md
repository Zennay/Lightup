# Emergency override is not scope authorization

Status: offline ST5 safety contract; **not** an implementation, approval, or production activation.

## Invariant

An operational emergency, incident ticket, elevated administrator role, manual runbook, or `break_glass` request flag **never creates or extends authorization** for any target-facing LightUp action. There is no emergency override path around the trusted scope gate. An emergency may only **reduce** authority (pause, revoke, quarantine, or stop work) until a fresh normal human approval is recorded through the existing trusted workflow.

## Reference decisions (all offline)

| Situation | Decision | Side effects permitted |
| --- | --- | --- |
| Target active; no valid scope grant; `break_glass=true` | Deny | None |
| Expired/revoked grant; incident responder has admin role | Deny | No target interaction |
| Valid grant; emergency STOP issued | Deny subsequent dispatch | Durable stop/audit record only |
| STOP later cleared without fresh valid grant | Deny | None |
| A new approval covers exactly the asset, capability, risk, tenant, time window and operator | Evaluate normal gate from scratch | Only ordinarily authorized actions |
| User-provided incident link or free-text approval assertion | Deny | None |

## Required separation

1. Incident severity and operator role are **context**, not authority. Reject any `emergency_override`/`break_glass` control when interpreted as a positive grant.
2. A stop/revocation event should invalidate queued, leased and retrying work at dispatch time. Do not revive stale snapshots after stop clearance.
3. A resumed task needs a fresh gate evaluation against canonical tenant, engagement, asset, exclusion, capability, risk, issuer, expiry and revocation state; no cached emergency permit.
4. Log bounded nonsecret denial reasons and actor/incident references without logging tokens or credentials.
5. An unreachable authorization store, clock uncertainty, malformed grant, missing approval or contradictory evidence means **deny**.

## Promotion criteria for future owner

Add isolated offline negative tests covering the table and zero handler invocations on rejection. Integrate only in the existing production policy/executor owners' branches after source-owner review and exact-head green CI on the permanent VPS runner. No real targets, network probes, deployment, or authority expansion are allowed by this document.
