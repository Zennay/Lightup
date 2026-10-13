# Scope #944 — exact outer RunContext at real ToolExecutor ingress

**LightUp INCUBATE M3/M7 · offline PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**

## Source and independence
Open [issue #944](https://github.com/Zennay/Lightup/issues/944) concerns untrusted outer `RunContext` object identity before any mode/risk/tenant/grant read. Original `ToolExecutor.execute` on source-owner [draft #107](https://github.com/Zennay/Lightup/pull/107), frozen SHA `c37ee27d922a7dd400eee1db39268f4a6269e431`, uses attribute access and accepts duck or subclass contexts. Field-level authorization and immutable dataclass do not establish *exact* outer type. No evidence of exploit against a real target is claimed.

This branch adds only two new paths (tests/docs), with no changes to original executor, grant writers, users, other workers or deployment. The existing composite #945 and field-level ownership remain untouched.

## New source-backed acceptance tests
`tests/test_scope_944_exact_runcontext_red_20261013.py` is a **real executor** suite, not a standalone policy oracle: temporary SQLite `StateStore`, inert in-memory `ANALYSIS` and `LAB_ACTIVE` handlers only, synthetic `synthetic.invalid` asset (never resolved or contacted). Nine tests include five **intentionally unresolved `unittest.expectedFailure`** around duck contexts, `RunContext` subclasses, duck claiming elevated lab authority, subclass lab impersonation and an attribute-access canary. Denial must occur before untrusted field reads/handler/evidence writes. Four ordinary controls prove canonical exact analysis/lab handling and mode/risk denial. A green run with expected failures is NOT a fixed executor.

## Production owner acceptance
1. At the very start of `ToolExecutor.execute`, accept only `type(context) is RunContext`; noncanonical duck/subclass fails closed before invoking any caller-controlled getters or handler.
2. Preserve all canonical context mode, risk, tenant, authorization, lab and evidence checks. This guards only the outer identity, **not** canonicality of nested grant or field values (#567/#771/#741 and related contracts).
3. Convert all five expected RED to ordinary PASS after integration into the original owner source, maintain independent positive controls.
4. Exact-final GitHub-hosted 3.11/3.14 and registered permanent VPS CI, latest-main composition, original owner/security/privacy review and explicit human release approval. No merge/deploy/real targets or scanning.
