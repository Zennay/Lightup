# Issue #950 — combined evidence-ledger and live-grant integrity contract

**Posture:** INCUBATE M3/M7; PLAN/LAB ONLY; **DRAFT/HOLD — NO MERGE / NO DEPLOY**.

## Ownership and exact parent

Stacked directly on original `ToolExecutor` source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107), frozen parent commit `c37ee27d922a7dd400eee1db39268f4a6269e431`. This branch adds **only** the new test module and this handoff document. It does not modify `src/lightup/ai/orchestration.py`, `src/lightup/state.py`, `src/lightup/execution_policy.py`, issue #170's SQLite-provenance work, existing PR #1295 / #1299 acceptance branches, any runner or production wiring.

## The combined security boundary

Both conditions must hold **together** before a TARGET_ACTIVE call reaches the handler:

1. The evidence sink is **exact** `StateStore` and remains bound to the constructor-selected ledger for the executor's lifetime. A duck ledger or swapped ledger must not claim success without a durable evidence record.
2. The live revalidation result is an **exact** `AuthorizationGrant`, not a same-ID duck/subclass. It must pass original grant identity and policy gates; untrusted live scope values must not mint asset authority.

An authentic grant with a forged sink, an authentic sink with a same-ID duck grant, and both forgeries at once must all fail closed **before policy/handler/evidence side effects**. Combining one guard with the other must not weaken either guard.

## Executable offline acceptance

`tests/test_scope_950_combined_ledger_resolver_red_20261013.py` invokes the **actual source-owner executor and policy**, a safe in-memory handler and disposable SQLite; every asset is reserved synthetic `.invalid`. It uses ten `unittest` methods:

- Four deliberately **unresolved expected RED** obligations: forged ledger with canonical live grant, forged live grant with real ledger, dual forgery, and postconstruction ledger replacement. Each requires no handler, untrusted ledger write or durable evidence on denial. `expectedFailure` is **not** evidence of a production fix.
- Six ordinary safety controls: canonical grant + real evidence persistence, missing ledger, missing live grant, different live ID, expired grant, and out-of-scope asset.

The original source owner should enforce these invariants in real `ToolExecutor` without trusting unvalidated duck objects, turn the four RED cases into ordinary passing tests, and preserve all existing mode, risk, consent, revocation, capability and asset checks. This contract does **not** fix #170's connection-local foreign-key issue.

## Verification and release handoff

Run exact-child-head Python 3.11 and 3.14 hosted/offline unit + real-producer canaries. Independently require a permanently registered `[self-hosted, zcloud, vps]` LightUp job at the **same final SHA**, plus latest-main composition and independent source-owner / security / privacy review. No GitHub-hosted result substitutes for permanent VPS proof. Explicit human release authorization is mandatory; do not merge or deploy this draft.

No DNS, sockets, real targets, scanning, arbitrary shell, model execution, customer grants or active assessment are used.
