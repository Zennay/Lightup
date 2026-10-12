# Scope #1173 — request-level pending-only cancellation, local acceptance (2026-10-12)

Status: **LOCAL ONLY / DRAFT HOLD / NO MERGE / NO DEPLOY**. This note does not contain a source implementation on this branch and is not evidence of canonical CI.

A previously withdrawn request in the opt-in `destructive_lab_review_queue.py` was hidden only by `withdrawn_at`. Restoring that column to NULL in an imported/stale SQLite row made the same request visible again despite prior withdrawal. The seven broader cancellation tombstones did not cover a single-request cancellation.

Local candidate v14 (not committed to GitHub) adds:
- `lab_review_cancelled_requests(request_id PRIMARY KEY, cancelled_at)`, written atomically with the exact tenant/engagement/run-bound withdrawal.
- An eighth read-side tombstone check shared by `get_pending`, `pending_for_run`, and `pending_for_tenant`.
- Rejection of repeated withdrawal after stale flag restoration, and rejection of UUID reuse after deleted row/import.
- Failure atomicity if tombstone insert fails, exact-scope isolation, and concurrent withdrawal regression tests.

**Local evidence:** 84/84 disposable-SQLite tests passed, repeated 15 times; Python compileall passed. This is *not* hosted or permanent self-hosted CI. The source/tests patch must be uploaded and independently verified before this branch is eligible for a PR merge. Do not claim the code is integrated.

This queue never approves, grants, revokes issued grants, dispatches tools or attests lab isolation. Caller authentication, real lab isolation, immutable registry, owner integration across every risk-5 entrypoint, independent review and exact-head permanent VPS CI remain required. No active scanning or real targets.