# Scope #951 — Monotonic live authority for an immutable run

**Safety:** LightUp INCUBATE M3/M7, PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY.

## Distinct ownership

This is an independent, new-path-only acceptance branch above exact source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) frozen commit `c37ee27d922a7dd400eee1db39268f4a6269e431`. #107 retains exclusive ownership of `ToolExecutor.execute`, `DomainStore`, production wiring, actual grants and state. This issue #951 covers **scope assets, capabilities, exclusions and max-risk** subset checks. The separate issue #953 owns temporal-window monotonicity. Do not merge either as an authorization patch.

## Required monotonic relation

Let `S` be the immutable original `RunContext.authorization`; let `L` be the same-id live grant. Live approval cannot increase the authority of an existing run. A valid successor needs:

- Every *effective permitted* live asset to have been permitted by the snapshot. Merely comparing allowlist tuples without considering exclusions is insufficient.
- Every live allowed capability must already exist in the snapshot; an empty original capability tuple is not authority.
- `L.scope.max_risk <= S.scope.max_risk`; narrowing risk does not compensate for any expanded asset/capability authority.
- All existing current live scope, tenant, engagement, revocation, activation, and target safety checks still apply.
- Any widening must be rejected before invoking the handler or writing evidence, even when the particular call appears otherwise safe.
- Neither grant is mutated. Historical run contexts cannot be rewritten to broaden scope.

This does **not** by itself prove canonical host equivalence, real persisted lineage, datetime validity, DNS binding or actual customer consent. Those are separate gates.

## Tests implemented

`tests/test_scope_951_live_authority_monotonicity_red_20261013.py` uses actual #107 `ToolExecutor.execute` and exact registered TARGET_ACTIVE `ToolDefinition` with a **totally inert** in-memory handler; no transport, sockets, network or target-capable worker. An inert result is stored only in disposable SQLite on authorized synthetic control cases. Synthetic asset names use reserved `.invalid` TLD.

Ten tests: five intentionally unresolved `unittest.expectedFailure` RED probes: new asset, added capability, raised max-risk, removal of existing asset exclusion, and mixed risk narrowing + capability widening. Five ordinary controls: unchanged valid dispatch, simultaneous narrowing across three dimensions, and independent narrower asset/capability/risk denials. All denied paths require zero handler calls and no evidence writes. A green unittest summary that contains the five expected REDs must **not** be interpreted as safe or fixed.

## Production owner acceptance

The source owner should implement **one monotonic comparison from immutable grant snapshot to trustworthy live record before any dispatch**, including effective asset-set semantics and exclusions, and convert each intentionally expected RED into an ordinary passing regression. Preserve current valid narrow intersections. Never accept an unauthorized replacement grant merely because the grant ID matches.

Verify on exact-final-head hosted Python 3.11/3.14, separately registered permanent VPS runner, current-main compatibility, original source owner and independent security/privacy review plus explicit human authorization. Until then remain DRAFT/HOLD, no merge, deployment, scans or activation.

Issue: https://github.com/Zennay/Lightup/issues/951
