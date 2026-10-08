# Scope authorization incident-response runbook (offline, proposed)

Status: operational acceptance criteria only. This runbook grants **no** permission for target interaction. M7/ST5, fail-closed.

## Trigger and containment
Trigger on revoked/expired authorization, suspected cross-tenant grant reuse, unexpectedly widened grant, stale queued job, resolver failure, or failed denial audit.
1. Identify the exact tenant, assessment/run ID, grant identifier and immutable grant snapshot. Treat identifiers as sensitive; avoid putting raw tokens or credentials into incident tickets.
2. Stop **new** TARGET_ACTIVE dispatch for that authorization lineage. Preserve unrelated tenant jobs. Do not stop unrelated tenants on identifier similarity alone.
3. Re-resolve grant from authoritative durable state; a cached object, previously approved UI state, queued payload or a same-ID replacement is not sufficient.
4. Mark queued/retry items as non-dispatchable when the current grant is missing, revoked, expired, broadened or otherwise inconsistent with the original approval.
5. For in-flight actions, signal bounded cancellation and confirm a checkpoint before any subsequent target step. If immediate interruption cannot be guaranteed, disclose that limitation and prohibit additional actions.

## Evidence and audit
- Append tenant-scoped denial and containment events to canonical audit storage with timestamp, run/grant lineage, decision, and non-sensitive reason. Never fabricate completion evidence.
- If audit storage is unavailable, maintain denial; surface an operational error and capture a minimal protected failure receipt. Do not turn an audit failure into permission.
- Preserve already-produced evidence according to retention rules. Revocation does not retroactively erase performed actions.
- Separate operator-facing incident status from externally shareable customer summaries; redact credentials and authorization artifacts.

## Restoration (never automatic)
- Restoration requires a **new** explicit approval decision and new run context bound to the precise tenant, assets, capabilities, time window and maximum risk.
- Do not reactivate a revoked run by changing status fields, retrying an old queue item or reusing the same grant ID.
- Verify current grant against original scope and live policy immediately before each new target-active action. Fresh approval never expands another tenant's authority.
- No actual target interaction is authorized by this document, tests, successful CI, or incident resolution.

## Inert acceptance exercises
| Exercise | Expected operational result |
| --- | --- |
| Revoke after queueing, before dispatch | No handler call; queued work denied |
| Expire during retry delay | Retry denied using current time and live state |
| Revoke during a multi-step handler | No subsequent target step after cancellation checkpoint |
| Simulate ledger outage during denial | Denial persists; operational error recorded separately |
| Reuse grant ID across two tenants | Only matching tenant/lineage considered; no cross-tenant permit |
| Replace grant with broadened scope | Old run denied; new approval/run required |
| Restore with fresh authorization | Only a new run can proceed after full fresh gate |
| Analysis-only operation | No upgrade to target-active capability |

## Release and incident closure checklist
- [ ] Source-owning implementation demonstrates denial at dispatch, retry and subsequent step on exact pinned commit.
- [ ] Tests use inert handlers, fake clock, local temporary state and no sockets/DNS/targets.
- [ ] Hosted and permanent VPS validation receipts independently reference the exact same commit and required test set.
- [ ] Reviewer confirms tenant boundary, cancellation limits and audit sink failures.
- [ ] Incident closure records residual risk and operator approval; CI green is not authorization.

Ownership: PR #107 holds ToolExecutor source; PR #954 executor evidence/resolver tests; PR #983 revocation transition matrix; PR #982 release receipts. This standalone document does not modify those work areas.
