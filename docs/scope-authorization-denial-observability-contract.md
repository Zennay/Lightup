# Scope-authorization denial observability contract (proposal)

Status: offline design/acceptance contract only. This document does not activate any target or authorize execution.

## Goal
When an authorization boundary rejects a requested action, operators need to distinguish a policy denial from a telemetry failure **without exposing sensitive authorization inputs**. Auditability must not become a secondary authorization channel.

## Minimum denial record
A denial may record: timestamp, opaque correlation ID, opaque tenant/run IDs already bound to the request, fixed enumerated denial category, fixed boundary identifier, and policy revision identifier. Default category is `AUTHORIZATION_DENIED`; avoid embedding untrusted exception messages.

Do **not** record credentials, bearer tokens, authorization references, raw URLs, query strings, request bodies, full asset inventories, tenant names, user-supplied target identifiers or freeform model output in a denial event. Secrets must not leak through tracing, exception fallbacks or debug-level logs.

## Fail-closed ordering
1. Parse and canonicalize tenant/run identity against the trusted store. Reject malformed or mismatched identities; do not log untrusted tenant IDs as authoritative labels.
2. Resolve the current approved grant and revocation state from trusted state; never infer approval from a denial record.
3. Evaluate target membership, capability, time window, risk and approval before any target-capable dispatch.
4. Commit denial evidence through a bounded, structured, non-target-capable path.
5. If required durable audit persistence fails, refuse dispatch. A telemetry outage must never allow a previously denied action to proceed. Whether to fail an otherwise eligible action on audit failure is determined by the production gate owner and must be explicitly documented.
6. Return a stable generic denial to untrusted callers. Granular internal reason codes are operator-only and must not reveal whether a foreign tenant/asset exists.

## Isolation and retention
- Cross-tenant reads require independent access control; a tenant must not filter arbitrary global denial logs by forged `tenant_id`.
- Event consumers are strictly non-authoritative: replaying or editing audit rows cannot issue or revive a grant.
- Bound event size and cardinality. Rate-limit repeated denials per trusted identity; preserve an aggregate count without storing repeated attacker-controlled payloads.
- Define retention, access roles and deletion/export constraints before release; no retention guarantee is asserted by this proposal.

## Offline acceptance matrix
| Scenario | Required outcome |
| --- | --- |
| Unknown or foreign tenant | Denied; generic external message; no foreign existence leak |
| Revoked, expired, future or narrowed grant | Denied before dispatch; fixed internal category |
| Invalid capability or risk | Denied before dispatch; no raw input in event |
| Audit write failure at mandatory boundary | No dispatch; explicit internal audit failure signal |
| Attacker-supplied exception with secret | Secret absent from log, traceback, response and metrics labels |
| Replay of an old denial event | No restoration of authorization |
| Many repeated invalid requests | Bounded event size/count; no unbounded label cardinality |
| Authorized request | The denial-audit component cannot independently grant execution |

## Ownership and next gate
This is a review contract, not a claim that production logging implements these behaviors. The executor/source owner (#107) and audit/storage maintainers must agree on mandatory persistence semantics and add real integration tests before any promotion. Existing #982 release receipts and #983/#989 revocation work are independent; do not edit or bypass those branches. Hosted and permanent VPS exact-head evidence are still required. No network, target interaction, handler invocation, grant issuance or active testing is part of this document.
