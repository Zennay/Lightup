# #896 — Live grant-ID integrity composition on activation pack #887

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a test/documentation carrier, not a production authorization patch or release approval.

## Immutable ancestry and ownership

- Direct pinned parent: `4153ff1422d2fe3e9221b92edac3b39935d2f8d9` (`chatgpt/scope-authorization-grant-activation-on-146-20261007`, issue #887).
- That parent is stacked above source-owner PR #146 (`33c67f8e8b17bd9214c29d02fc52954cc42655da`), which incorporates prior PR #107 source ancestry. Neither parent nor owner branch is modified.
- Imported **unchanged, blob-for-blob** from original #873 acceptance branch HEAD `96e287701fe6f21ff0ca40efd306da2ce8632276`:
  - `tests/test_scope_authorization_live_grant_id_identity.py` (original blob `0cb0a2b32b8076ae0a9855194415e586ff2abdca`).
  - `docs/scope-authorization-live-grant-id-identity.md` (original blob `22bf49b91c6f48d36a33a7a452e568660e695aeb`).
- This composition receipt is the only new-original content. All three paths are additions; **zero edits to existing test/source/workflow/runner files**. Issue #896 deliberately does **not** claim ownership of PR #107/#146's resolver, executor, domain, grant issuance or risk-decision implementation.

## Acceptance coverage

Original #887 parent tests remain unchanged:
- #888: canonical durable 0/1 recurring-retest marker, green on source-parent when recorded.
- #881: ELEVATED issuance requires approved same-engagement risk step-up (source RED).
- #884: RUNNING engagement requires current unrevoked matching grant (source RED).
- #890: explicit malformed falsy `now` must not silently substitute wall time (source RED).

Carried #873 tests execute against **installed project implementations** using only temporary SQLite and a fictional in-process handler:
1. Canonical exact-string persisted grant-ID is accepted and writes one synthetic evidence row (ordinary positive control).
2. A **non-string SQLite-adaptable** object masquerading as that ID must be rejected before any handler invocation/evidence mutation (expected existing-source RED).
3. A matching-text **`str` subclass** must be rejected before handler/evidence mutation (expected existing-source RED).

A failing security assertion here is an *unfixed contract*, not a successful security gate. Do not reinterpret an expected RED as PASS, and do not use this branch as a valid client grant or dispatch capability. Any subsequent source-owner correction must preserve original grant/tenant/engagement, revocation, risk, scope, expiry, canonical grant snapshot checks and the zero-handler-on-denial property, then turn REDs into ordinary PASS after independent review.

## Verification and release boundary

Verify the exact child HEAD and Git comparison against the pinned parent: it must be **3 added paths, 0 edits/deletes and zero behind**; verify the two reused file blob SHAs match the originals. No runtime tests or hosted/VPS CI runs are claimed by merely copying the files.

Per issue #896/#887, **do not create or retrigger permanent self-hosted LightUp CI while the shared VPS lane is occupied**; preserve all other workers' queue/run state. The source-owner integration and a later exact-head hosted + registered `[self-hosted,zcloud,vps]` VPS proof, independent security/privacy review, authentic customer/operator approval, live durable grant/revocation proof and explicit human release GO are still required.

No DNS, external network, real targets, scans, real grants, target-capable execution, merge, deployment, remediation, verdict or attack-path action is authorized by this composition.
