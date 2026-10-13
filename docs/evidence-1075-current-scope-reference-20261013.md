# Evidence remediation #1075 — opt-in current-scope lookup reference

**Date:** 2026-10-13  
**Stacked parent:** own [DRAFT PR #1266](https://github.com/Zennay/Lightup/pull/1266) pinned exact `e3bdf85b4c2ec1c863188cf77c197c3540cf5925`.  
**Issue:** [#1075](https://github.com/Zennay/Lightup/issues/1075) — installed `StateStore.get_evidence` still admits noncanonical, potentially historically stored IDs.  
**Stage:** LightUp **Incubate M3/M7 — PLAN/LAB ONLY**.

## Why a separate isolated child

The earlier #1199 canonical UUID4 validator and #1265 tests deliberately do **not** change default `StateStore`. The historical ID inventory #1266 provides a compatibility census only and cannot establish tenant or grant authority. This new child shows a composable **reference** admission order while keeping all original source-owner files untouched; it is **NOT installed in production** and it does not provide an authenticated session, policy decision or grant service.

## Optional adapter

`src/lightup/evidence_scoped_lookup_reference.py`:

1. Accepts only an exact built-in, lowercase, hyphenated RFC4122 UUID4 evidence selector *before* any scope checker callback or persisted evidence read. Reject str subclasses, alias spellings, type confusion and historical legacy strings; no normalization or migration.
2. Refuses malformed caller-supplied scoped run/capability reference labels, missing scope checker or checker error. The `check_current_permission(run_id, capability_id, evidence_id)` callback is **trusted/injected** by the caller and must return **exact built-in `True`**, not `1`, truthy text or permissive None. A synthetic `lambda True` used in tests is **not a real permission system**.
3. On positive *injected* current-scope reference check, delegates to real unmodified `StateStore.get_evidence`, checks returned `EvidenceRecord` exact class and run/capability/evidence identity, rechecks the injected permission callback before yielding the record. Unknown selectors and invalid persisted metadata produce a generic unavailable error; mismatches, callback errors or revocation return generic denied errors without leaking raw evidence or exception content.
4. No writing, authorization grants, code execution, real remediation/retest, external provider/network or output of unreviewed client evidence. A database row matched to caller labels is **NOT** proof that caller labels are trusted, a user is authenticated, or a grant is authorized. A two-check reference is **NOT atomic with concurrent grant revocation** and must not be deployed as the final production boundary.

## Synthetic real SQLite acceptance

`tests/test_evidence_1075_current_scope_reference_20261013.py` supplies **14 unittest methods** with temporary actual `StateStore` SQLite files: canonical accepted, invalid IDs rejected before scope callback/lookup (multiple subtests), missing/refused/truthy/error current grant before DB, unknown canonical ID privacy, wrong run or capability row denial, grant revoked/throws between DB read and return, malformed scoped types, invalid persisted JSON privacy, and preserved unmigrated historical IDs. Every persisted record is synthetic. No live data/target permission is invoked.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_current_scope_reference_20261013
```

## Owner's mandatory integration stop line

- Historical compatibility and migration policy from #1266 (noncanonical legacy evidence must not disappear or silently rewrite).
- Original StateStore/tenant/security owner must prove authenticated context, trusted run/capability binding, action-time authorization and durable revocation. The injected reference callback **cannot** substitute for this.
- Original product `StateStore.get_evidence` remains unchanged; four deliberate installed-reader RED canaries in parent #1265 **remain unresolved**. Product source owner must integrate a properly authorized *production* prelookup gate and convert these XFAIL cases into ordinary green tests.
- Latest-main safe composition, privacy/security/tenant/source-owner review, exact-head GitHub-hosted Python 3.11/3.14 **and separate registered permanent VPS** CI, and explicit human release approval.

**DRAFT/HOLD — NO MERGE/NO DEPLOY.** No actual client database, real target, scanning, executed remediation/retest, grant creation, authorization promotion or runtime change.
