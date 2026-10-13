# Scope #935 — prevent instance-level ExecutionPolicy.decide rewiring

**LightUp INCUBATE M3/M7 · offline PLAN/LAB ONLY · DRAFT/HOLD / NO MERGE / NO DEPLOY.**

## Verified defect and ownership
Source [PR #107](https://github.com/Zennay/Lightup/pull/107) `ToolExecutor` receives an `ExecutionPolicy`. Issue #779 handles the **outer policy class** admission, while [issue #935](https://github.com/Zennay/Lightup/issues/935) identifies a separate gap: even an exact policy instance is mutable, and a later caller can inject `policy.decide = allow_all` while retaining the exact trusted instance identity. Such in-process tampering may bypass scope checks before an inert test handler runs. No claim of malicious external exploit.

This independent branch starts on frozen original PR #107 SHA `c37ee27d922a7dd400eee1db39268f4a6269e431`, adds NEW tests/docs only, does NOT modify production `src/lightup/execution_policy.py` (owner #100), original `ToolExecutor` (owner #107), #779 outer identity owner, existing other workers or deployment.

## Implemented regression matrix
`tests/test_scope_935_execution_policy_instance_integrity_red_20261013.py` runs the authentic original `ToolExecutor.execute` and `ExecutionPolicy` with synthetic reserved `.invalid` assets, a disposable SQLite evidence store and a no-IO in-memory TARGET_ACTIVE handler; no transport, DNS, model, grant issuance, real target or scan.

Nine methods:
- Four deliberately unresolved `unittest.expectedFailure` RED: direct `policy.decide` assignment, `object.__setattr__`, instance dictionary shadowing, and bulk dictionary update. Each must leave `policy.decide` unchanged, preserve out-of-scope denial and write no handler/evidence.
- Five ordinary controls: genuine out-of-scope denial, synthetic authorized-in-scope success, missing-grant rejection, passive-mode restriction and canonical original class method identity.
- `OK (expected failures=4)` is **not** a security fix. The source owner must eliminate these RED cases, then remove `expectedFailure` entirely so ordinary PASS proves the invariant.

## Release contract
Owner #100 implements immutable canonical policy instance behavior; owner #107 ensures correct executor composition without accepting arbitrary rewired policy. Preserve existing risk/tenant/capability/expiration/grant checks, do not treat Python in-process reflection as a tenant security boundary. Require original source owner and independent security/privacy, exact-final hosted Python 3.11/3.14 plus permanently registered VPS runner, latest-main integration and explicit human release permission. No merge/deploy/activation from these tests.
