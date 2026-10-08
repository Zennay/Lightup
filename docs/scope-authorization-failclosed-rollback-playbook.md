# Scope authorization: fail-closed rollback and incident playbook

Status: **proposal / operator-only guidance** (M7/ST5). This document is not evidence of deployment readiness, an authorization grant, or permission to interact with a target.

## Purpose and ownership

This playbook is for the owner of the production authorization admission boundary and the release operator. It defines what to do when scope authorization, revocation, live grant resolution, or its evidence chain cannot be trusted. Production implementation is owned separately (notably executor integration tracked by #107). Existing release-evidence work remains with its owning PR; this document does not replace its gates.

## Trigger conditions

Treat any of the following as a stop condition, even if a healthy response or passing unit test was previously observed:

- An unrecognized, expired, revoked, cross-tenant, broadened, or ambiguously parsed grant appears accepted.
- Grant lookups or revocation freshness cannot be established at decision time.
- Tenant/asset/capability/risk/mode/issuer identity cannot be tied to the request and exact running authorization.
- The executor can dispatch before the admission decision, or reject paths enqueue work or create target I/O.
- Evidence provenance, exact code revision, or canonical runner results are missing or contradictory.
- A previously approved release introduces a newly exposed authorization path without equivalent gating.

## Containment — no target interaction

1. Stop **new active admissions** using the existing operator-controlled disable mechanism. If no reliable fail-closed switch exists, stop the affected worker/service through its documented service owner; do not improvise a new live command from this runbook.
2. Prevent queued work from acquiring new active authorization. Keep passive/offline processing only if its isolation from the affected path is demonstrated.
3. Preserve immutable incident metadata: UTC detection time; environment; build/commit SHA; image digest if available; affected tenant and opaque run/grant identifiers; the precise boundary and observed decision; revocation source and freshness state. **Do not copy grant secrets, credentials, access tokens or raw customer payloads into tickets.**
4. Notify the production-executor owner, scope-authority owner, and release operator. Classify all affected grants/runs as untrusted until reviewed.
5. For any potentially affected customer environment, require designated human authorization/incident handling before resuming. The playbook never authorizes verification against a real target.

## Restore and rollback decision

- Prefer reverting to the last **independently evidenced** revision with the same or narrower authorization policy. A successful build alone is insufficient.
- **No automatic fallback** to broader grants, stale cached approvals, disabled revocation, synthetic authority, lower risk thresholds, or lab bypass modes.
- If the previous revision does not satisfy the current authority contract, keep active admission disabled. Availability is subordinate to authorization correctness.
- Run offline negative tests against the exact rollback candidate: malformed envelope, unknown interaction type, foreign tenant, expired/revoked grant, expanded asset/capability/risk/validity, denied request with zero dispatch/queue/target side effects.
- Verify exact candidate SHA in hosted checks and canonical permanent-VPS CI, when available; preserve run URLs and result conclusions. A queued or cancelled run is **not** green.
- Restore only after source-owner review and independent release approval. This document does not itself approve a rollout.

## Explicit reopen criteria

All statements below must be supported by linked evidence, not asserted from a draft PR:

- [ ] Authorized source owner identifies the corrected boundary and exact release revision.
- [ ] Runtime admission revalidates canonical live issuer, tenant, asset, capability, scope, expiry, revocation and approved risk for every active dispatch.
- [ ] Invalid inputs and unavailable dependencies deny **before** dispatch, queue publication or target I/O.
- [ ] Run-snapshot authority is never enlarged by a later live same-id record, including its validity window.
- [ ] Offline negative and positive controls pass for the exact code revision, with explicit side-effect assertions.
- [ ] Hosted preflight and permanent-VPS CI report successful conclusions for that same SHA; all exceptions are documented as unresolved rather than silently waived.
- [ ] The operator has a tested disable/rollback mechanism, a named owner and a traceable release decision.
- [ ] Separate human approval and digital scope authorization exist for any eventual real-target activity.

## Record template

```text
Incident ID:
Detected UTC:
Reporter / owner:
Affected environment:
Exact candidate SHA:
Last verified safe SHA:
Admission disabled at UTC / by:
Evidence links (no secrets):
Offline test conclusion:
Hosted check run + conclusion:
Permanent VPS run + conclusion:
Grant/revocation data integrity review:
Authorized release approver:
Reopened UTC / by:
Outstanding gaps:
```

## Non-goals

No production-source edits, runner dispatch, service manipulation, scanning, credential handling, target verification, deployment, or automatic enablement are prescribed by this document. Release operators must use their separately approved operational procedures.
