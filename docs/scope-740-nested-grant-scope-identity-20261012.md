# Scope authorization #740 — exact nested grant scope admission

**Phase:** LightUp Incubate M3/M7 PLAN/LAB ONLY. **DRAFT/HOLD/NO MERGE/NO DEPLOY.**  
**Pinned source owner:** [Draft PR #100](https://github.com/Zennay/Lightup/pull/100), exact source owner commit `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`. This independent branch does not edit owner source.

## Root cause / required invariant

A dataclass annotation on `AuthorizationGrant.scope: ScopeDefinition` does not ensure runtime identity. The original `ExecutionPolicy.decide(TARGET_ACTIVE)` reads the nested object's `max_risk` then calls its `allows_asset` and `allows_capability` methods. A `ScopeDefinition` subclass overriding either method, or a duck-typed scope object, can supply decisions from untrusted caller-defined code rather than the actual canonical immutable scope contract.

**Required owner repair:** require `type(grant.scope) is ScopeDefinition` at the trusted active decision boundary **before** any nested field, risk comparison, grant scope method, handler or target operation. Issuance-side exactness and durable re-resolution are separate checks and do not replace this direct policy constraint. No polymorphic bypass, wrapping, coercing, truthiness or spoofed scope object may create authority.

## Dedicated, new test path

- `tests/test_scope_740_exact_nested_grant_scope_red_20261012.py`: **13 synthetic in-memory unittest methods**.
- **6 intentional expected-RED** before original source-owner repair: malicious scope subclass supplies asset authority, another subclass supplies capability authority, harmless subclass exact-type rejection, duck-typed authority, missing nested max-risk must deny without attribute error, and foreign scope call/side-effect avoidance.
- **7 ordinary canonical controls**: legitimate exact scope success, foreign asset/capability denial, exceeding max risk, missing grant, input immutability and expired grant denial.
- All target names are reserved `.example.test`; no DNS, socket, HTTP, handler, authorization issuance, network, scanning, actual client or remediation activity.

## Reproduction / evidence boundary

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_740_exact_nested_grant_scope_red_20261012.py' -v
```

**Not yet run or CI-accepted**. Expected failures are evidence of unfixed installed original behavior, **not repaired security**. This tests/docs-only branch has intentionally **no PR or workflow dispatch** while the permanent VPS LightUp runner is occupied. Require actual owner fix, conversion of XFAILs to ordinary passing denial tests, exact-head hosted Python 3.11/3.14 full unit and genuine producer integration logs, independent registered permanent VPS CI, review of trusted issuer/tenant/grant/capability/asset/risk/window/revocation/destination gates, safe current-main composition and explicit human release approval. It has no deployment authority.
