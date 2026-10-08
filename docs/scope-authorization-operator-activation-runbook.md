# Scope authorization — operator activation and rollback checklist

Status: **non-authoritative operations checklist**. This document grants no permission and does not enable real-target execution. Production implementation remains owned by the active scope/executor owners.

## Before enabling any real-target capability

1. Identify the exact deployment SHA, accountable operator, requesting tenant, engagement, explicit asset identifiers (canonical hosts/CIDRs), approved capability set, risk ceiling, validity window and authorization owner/reference. Do not interpret discovery, simulator output, AI output, or a prior run as authorization.
2. Obtain the recorded, independently verified client approval covering the same tenant, engagement, assets, capabilities, risk and time window. Unknown, incomplete, revoked or conflicting fields mean **DENY**.
3. Verify the current server-side policy and grant at the **moment of dispatch**; a previously accepted queued plan, cached response, human emergency flag or signed-looking document alone does not suffice.
4. Require an execution-specific proof that the selected target and tool are subsets of the approved grant, with no implicit wildcard, alias, redirect, inherited permission or elevated-risk fallback.
5. Verify that the deployed executor has a single common fail-closed boundary for each network-capable adapter, including background jobs, retries and retests. Refuse activation while any bypass remains.
6. Collect successful tests for malformed/unknown tenant, cross-tenant access, expired/not-yet-valid/revoked approvals, clock failures, unexpected tool/risk enum types, missing resolver, cache expiry, identity mismatch, concurrent revocation and stale queued work. Include positive lab-only controls.
7. Require **exact-head** successful hosted preflight and canonical permanent self-hosted VPS CI, plus source-owner review. A green run for an older SHA is insufficient.
8. Record a deliberate human decision to activate a separately configured deployment feature; default remains disabled. No permission is inferred from merging a PR or publishing this checklist.

## Abort/rollback — immediately deny new and queued dispatch

- On an approval withdrawal, unknown authorization state, emergency override, source disagreement, deployment drift or failed revalidation: stop **before** outbound target I/O and evidence write.
- Disable the explicit activation switch; reject queued and retry jobs until their authorization is freshly revalidated. Do not assume existing leases, caches or prior decisions remain valid.
- Preserve a sanitized operational audit trail: UTC timestamp, correlation ID, tenant-safe decision ID, deployment SHA, outcome and reason category. Do not log credentials, full tokens or unapproved target details.
- Investigate using offline fixtures or explicitly authorized lab targets only. Re-enable only after the failed gate is fixed, exact-head CI is green and the accountable human approves the new activation.

## Evidence record (fill for each activation)

| Required item | Evidence / link |
| --- | --- |
| Deployment commit SHA and approved build | Not supplied — DENY |
| Client authorization reference and scope | Not supplied — DENY |
| Tenant/engagement/asset/capability/risk/time validation | Not supplied — DENY |
| Executor/adapters fail-closed review and tests | Not supplied — DENY |
| Exact-head hosted CI and canonical VPS CI | Not supplied — DENY |
| Owner approval, activation time and rollback owner | Not supplied — DENY |

**This is not proof of authorization.** All empty/placeholder rows are denial conditions. No production code, deployment configuration, target interaction or network test is part of this change.
