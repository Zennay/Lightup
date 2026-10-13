# Issue #940 — Exact canonical registry and immutable ToolExecutor binding

**LightUp status:** INCUBATE M3/M7 PLAN/LAB ONLY; **DRAFT/HOLD / NO MERGE / NO DEPLOY.**

## Real source finding

Source-owner [draft PR #107](https://github.com/Zennay/Lightup/pull/107) permits any duck-typed `registry` constructor argument and retains it in a mutable `ToolExecutor.registry` public attribute. This can let caller-controlled `get` supply handlers and metadata without the canonical `ToolRegistry.register()` admission path. Assignment after construction can also replace the registry. It is an **offline object integrity boundary**, not evidence of exploitability against actual user processes.

## Ownership isolation

Issue [#940](https://github.com/Zennay/Lightup/issues/940) is scoped to exact registry type and executor lifetime binding. This new-path-only DRAFT branch starts directly from original #107 frozen SHA `c37ee27d922a7dd400eee1db39268f4a6269e431`. Original executor #107 and canonical registration/schema owner #156 remain untouched. Other neighboring issue contracts #938 (live resolver), #949 (resolved grant), #951 (asset/capability/risk), and #953 (validity windows) each have their own independent owners/drafts. No production code, other branches, main or installed runners are changed.

## Genuine test implementation

`tests/test_scope_940_canonical_registry_binding_red_20261013.py` uses the real PR #107 `ToolExecutor.execute` with a canonical tool registry, an inert registered `ANALYSIS` handler, a simulated duck registry, subclass registry, a disposable SQLite `StateStore`, and reserved `.invalid` synthetic asset names. No DNS, sockets, target interaction, grant issuance, active scanning, model output or deployment.

Nine isolated regression methods:

- **Five intentionally unresolved expected RED**: duck registry accepted at construction, subclass registry accepted at construction, postconstruction public attribute replacement, `object.__setattr__` replacement and instance dictionary shadowing.
- **Four ordinary controls**: canonical analysis tool allowed and evidence persisted locally, mandatory non-null evidence ledger, unknown tool denied before handler/evidence and passive context unable to dispatch a TARGET_ACTIVE tool.
- Every rejected/noncanonical construction path must have **zero handler calls and zero evidence writes**.
- A test run showing `OK (expected failures=5)` is *not* an authorization fix. All five must become ordinary PASS in original source owner implementation.

## Required original owner fix

1. Require `type(registry) is ToolRegistry` on construction, not a duck or subclass. No policy, target handler or evidence source may rely on arbitrary metadata.
2. Pin trusted constructor registry for the executor lifetime, resisting public reassignment, dictionary shadow and `object.__setattr__` (within the realistic process threat model).
3. Convert all five expected RED tests into ordinary green; preserve canonical positive controls, mode/risk/tenant/authorization checks, and source-owner #156 registry definition/schema contract.
4. Require exact final head hosted Python3.11/3.14 and separately registered permanent VPS CI, independently reviewed latest-main composition, privacy/security and explicit human release permission.
5. Do not merge/deploy, activate, scan or test real targets from this independent acceptance branch.

This test pack does not prove safety against arbitrary Python reflection or external caller compromise.
