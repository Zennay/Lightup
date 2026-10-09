# Scope authorization: production proof manifest (owner handoff)

Status: **HOLD / non-executable**. This document describes acceptance evidence; it does not authorize targets, change policy, or assert production readiness.

## Exact implementation identity
Fill in only from observed CI/owner evidence:

| Field | Evidence |
| --- | --- |
| Reviewed implementation SHA | TBD |
| ToolExecutor owner PR / review | TBD (#107) |
| Trusted destination-metadata integration | TBD (#1093) |
| Destination argument binding | TBD (#1092) |
| Persistent grant source and revision | TBD |
| Hosted Python 3.11 / 3.14 workflow + SHA | TBD |
| Permanent VPS runner workflow + SHA | TBD |
| Negative I/O trace artifact | TBD |
| Positive local-lab trace artifact | TBD |

**Release rule:** all evidence must refer to the same immutable implementation SHA. A queued, cancelled, skipped or successful *other-SHA* run never satisfies the gate.

## Instrumented acceptance scenario
Run exclusively with an isolated offline lab and instrument the real production `ToolExecutor.execute` boundary. Stub or deny DNS resolution, sockets, subprocesses, HTTP clients, retries, persistence writes, and queue submission; count invocation attempts at every boundary, not only successful responses. Never use a real target.

1. Instantiate a persisted tenant-scoped, asset-scoped, capability-scoped grant with a trusted issuer, revision, risk approval and validity interval. The caller must not be able to substitute or mutate this stored record.
2. Negative cases (separately): missing grant; mismatched tenant/engagement/asset/capability; issuer mismatch; risk escalation; expired or not-yet-valid grant; revoked grant; stale revision; corrupt validity timestamps; crafted endpoint/host/port/port-set arguments that diverge from the authorized asset; caller-declared destination roles.
3. Revalidate the grant and destination binding **immediately before each dispatch attempt**; introduce a deterministic revocation between planning and dispatch, then between first attempt and retry/redispatch. All attempts after revocation must deny.
4. For every denied case assert: **zero handler calls, DNS calls, socket opens, HTTP calls, subprocesses, retry submissions, queued work, action-evidence writes and target-side effects**. A minimal sanitized denial-audit record is allowed and must never be counted as action evidence.
5. Positive control: an exact-match, owner-approved *loopback-only lab* grant dispatches exactly once through the instrumented executor; observe evidence semantics without external connectivity. Removing this control invalidates proof because blanket-deny is not the acceptance goal.
6. Independently verify parameter metadata and values: only registry-owned immutable destination roles are authoritative; exact built-in primitive types, finite numeric values, canonical identities and bounded port sets are checked pre-I/O.

## Failure modes and acceptance
- A missing trace counter is **unknown**, not zero.
- Any uninstrumented I/O escape is a failed test, not a skipped assertion.
- Any stale grant cache/replayed request after revocation fails the gate.
- Approval in a header, planner output, model response or request body is not issuer provenance.
- Passing mock/reference tests alone does not prove the real executor's enforcement.
- The production owner must review the exact changed code, and CI must prove both hosted Python versions plus the canonical self-hosted VPS lane on that exact SHA.

## Ownership and non-interference
This is a documentation-only reference pack. Do not merge or deploy it as production authorization. Do not modify #107, #1092, #1093, other workers' branches, or canonical runner scheduling from this lane. Real target activation stays disabled until explicit human authorization and all proof gates are satisfied.
