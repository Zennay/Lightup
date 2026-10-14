# Scope state provenance FK gate — #170 (14 October 2026)

This opt-in probe is **offline, disposable, and non-authorizing**. It addresses the observed `StateStore` connection-local foreign-key gap without modifying owner-managed `src/lightup/state.py`, `src/lightup/ai/orchestration.py`, PR #167/#156/#169, any existing tests, workflow, runner, or deployment.

## Commands

```sh
python -m unittest discover -s tests -p 'test_scope_state_fk_offline.py' -v
python scripts/check_scope_state_fk_offline.py
```

The script imports the real `StateStore`, creates a **new throwaway SQLite DB** in a temporary directory and checks (1) foreign keys enabled on subsequent connections, (2) orphaned evidence denied, (3) orphaned lease denied, (4) legitimate plan-only run evidence still works, (5) no orphan rows persisted. No existing customer or operator DB is ever opened; no real target, network, socket, DNS, scan, grant, or activation action occurs.

If all five synthetic controls pass, output is `REVIEW_ONLY` with exit 0. Otherwise `HOLD` with exit 2. Both fix `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved` to `false`. Exceptions are replaced by opaque `PROBE_UNAVAILABLE` receipts; no paths or secrets are copied into output. Tests exercise strict/permissive disposable stores, independent evidence/lease failures, cleanup, control run, and exception privacy.

**Expected on original main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`: HOLD** because `StateStore.connect()` does not enable FK on each newly opened SQLite connection. This is a genuine gap rather than a grant or real-target vulnerability demonstration. The test oracle allows future fixed implementations to return `REVIEW_ONLY` without rewriting the test to assert a permanent failure.

## Remaining owner gates

Issue #170 also requires persisting the **exact run provenance row before evidence**, checking `RunContext` mode and authorization-reference coherence, and failing closed under unknown-run IDs in the **actual executor**. This optional checker alone does **not** enforce those runtime invariants, provide trusted CI evidence, authorize a scope/target, or allow merge/release.

Before any production behavior changes: finish/rebase owner-managed work, review latest-main integration, verify immutable-head hosted Python 3.11/3.14 and genuinely executed permanent registered VPS CI, independent security/privacy/source-owner approval, and explicit human activation decision.

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**
