# M7/ST5 — scope-denial response confidentiality acceptance contract

Status: **reference-only / NOT runtime enforcement**. Scope: authorization read APIs and operator interfaces. Production owner of executor enforcement: #107. This contract must not grant access, activate a target, or change authorization policy.

## Threat boundary
An unauthorized caller must not infer whether another tenant, engagement, grant, asset, approval or queued assessment exists from a denial response. The denial itself must not become a cross-tenant discovery or timing oracle. A privileged internal audit trail may retain specific diagnostics only after independent operator authorization and tenant isolation.

## Acceptance matrix
| Case | Input differential | Required externally visible behavior |
| --- | --- | --- |
| Missing vs other-tenant grant | Same caller, random ID vs existing foreign ID | Same status and stable public error shape; no existence disclosure |
| Expired vs revoked vs never-issued | Same caller without read authority | Uniform denial without distinct remediation hints, counters, or tenant identifiers |
| Foreign tenant + malformed grant | Invalid and foreign selectors combined | Validate shape without lookup leaks; no durable mutation, no grant confirmation |
| Queue/job ownership mismatch | Existing foreign job vs unknown ID | No job state, progress, logs, worker name, runner URL, or evidence link |
| Approval requested/declined | Unauthorized user querying another engagement | No approval state or reviewer identity leak |
| Batch of mixed tenants | All authorized vs one foreign reference | All-or-nothing response; no per-item classification of foreign IDs |
| Correlation/request ID | Caller-provided identifier collides with internal audit ID | New server-owned correlation identity; never use caller ID as authority |
| Side effects | All denied paths | No target I/O, dispatch, queued worker, scan, grant issuance, or status mutation |
| Failure path | Policy service/store/audit unavailable | Generic fail-closed response; no diagnostic stack or secret fields |

## Required owner integration
1. At authorization API boundaries, separate authenticated caller identity from caller-supplied selectors. Enforce the same tenant/engagement gate before loading entity-specific fields.
2. Normalize public denial envelopes (response codes, field presence, headers and labels) across unauthorized existence classes. Internally distinguish reasons only in access-controlled logs.
3. Avoid differing validation/lookup ordering that creates an obvious existence oracle; measure distributions on controlled synthetic fixtures, not real external targets. **No strict constant-time claim is made** for web API responses.
4. Enforce authorization again on any pagination, export, event stream, polling or job-status subresource. Never include signed object URLs in denied responses.
5. Verify logging failure also denies before execution; audit messages must not include secrets or authorization tokens.
6. Add integrated negative tests against the *actual* API/controller and persisted store, proving zero mutations and zero target I/O. Offline reference checks alone are insufficient.

## Release blocker
Do **not** mark M7/ST5 green from this document. Production owner review, synthetic integration regressions, pinned exact-head hosted CI and permanent self-hosted VPS evidence, and explicit human release approval are required. This artifact introduces no network requests, real-target interactions, active tests, or deployment.
