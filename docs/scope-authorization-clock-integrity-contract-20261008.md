# Scope authorization: clock-integrity acceptance contract (M7/ST5)

Status: **design-only / not validated / not a runtime control**. Production authorization and dispatch implementation remains owned by the existing source owners. No target interaction or grant activation is authorized by this document.

## Security invariant

An approval, scope grant, or capability must never become valid again solely because a system clock moved backwards, a wall-clock source was replaced, a timestamp was rounded, or a worker resumed from a stale snapshot. Every target-capable dispatch must independently establish a current, authorized, tenant-bound scope and approval using the canonical authority. If clock integrity or authority availability cannot be established, deny without target I/O.

## Decision boundaries

1. Parse `issued_at`, `not_before`, and `expires_at` as strictly typed, timezone-aware UTC instants; reject absent timezone, strings with ambiguous local-time interpretations, nonfinite/overflowing values, reordered windows, and type coercions (including booleans as integers).
2. Require `issued_at <= not_before < expires_at` where applicable, and a configured finite maximum lifetime. Never treat missing expiry as infinite.
3. At issuance, validate against authoritative server time and persist immutable issuance identity/version with the grant; client clocks are not authorization sources.
4. At dispatch, require both an unexpired authoritative wall-time decision **and** a fresh durable authorization/revocation generation check. Monotonic clocks can measure intervals in one process but cannot replace persisted expiry across restarts.
5. A backward clock jump, unavailable or unsynchronized authoritative time source, impossible timestamp, or uncertainty that straddles the expiry boundary must fail closed and emit a redacted, bounded denial reason.
6. A forward clock jump may invalidate a grant early; it must never extend its lifetime. Reissuance requires a new explicit approval and generation, not a timestamp repair.
7. Background jobs, queues, retries and workers must not cache an allow decision across enqueue-to-dispatch, restart, revocation, approval expiry, or tenant/engagement change.
8. The evaluation must be stable under DST transitions and leap-day dates; all comparisons use UTC instants, not local wall-clock string ordering.
9. Denials preserve only minimally necessary evidence (grant identifier fingerprint, reason code, checked-at UTC and authority/version identifier), excluding secrets, tokens and target credentials.
10. Operators must not bypass the guard by changing server time, relaxing a cutoff or replaying an old approval. Recovery requires correcting trusted time, obtaining a fresh authorization state, and verifying the exact production source and tests.

## Offline negative test matrix (for integration owner)

| Case | Expected decision |
| --- | --- |
| Exactly at `expires_at` | Deny (exclusive expiry) |
| Exactly at `not_before` with otherwise valid current state | Eligible for further checks, not an automatic allow |
| One tick before `not_before` | Deny |
| Expired grant followed by wall-clock rollback | Deny, no reanimation |
| Clock uncertainty overlaps expiry boundary | Deny |
| Unavailable trusted time source | Deny |
| DST fall-back and spring-forward local representations | Normalize to UTC or reject ambiguity |
| Process restart with old monotonic timestamp | Revalidate from durable authority, never trust old monotonic reading |
| Queued task approved earlier, revoked before dispatch | Deny |
| Expiry parsed from bool, float infinity, naive datetime or huge exponent | Reject schema |
| Valid timestamp but wrong tenant/engagement/asset | Deny |
| Forward clock leap | Never extend validity; deny if outside validity window |

## Release evidence required

The production owner must link each matrix row to a source-integrated regression that exercises the actual dispatch guard, and capture exact-head hosted CI **and** canonical permanent-VPS runner results. Include test names, commit SHA, denial/no-target-I/O assertion, trust-source failure injection, and evidence for current generation/revocation revalidation. Maintain draft/PLAN-LAB ONLY until reviewed and proven; this contract is not evidence of deployed enforcement.

## Ownership boundary

This file is intentionally standalone and documentation-only. It does not modify domain, scope, approval, execution-policy, executor, redaction, target adapters, deployments, or other workers' branches and does not supersede current release gates.
