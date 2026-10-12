# Scope-authorization #773 — direct max-risk exact enum acceptance

**Branch-only, tests/docs only; source-owner handoff.**  
**Source owner:** [PR #100](https://github.com/Zennay/Lightup/pull/100), immutable parent SHA `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.  
**LightUp:** Incubate M3/M7 PLAN/LAB-only — **DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Confirmed source-level gap

`ScopeDefinition.max_risk` is a dataclass annotation and is not runtime-validated for exact `RiskLevel`. In `ExecutionPolicy.decide`, a TARGET_ACTIVE request compares `requested_risk > grant.scope.max_risk` numerically. A direct caller can supply `99`, `99.0`, a foreign `IntEnum(99)`, or a bool value instead of the canonical enum. A valid synthetic authorization and tenant binding can then pass a risk ceiling that was never authorized as a genuine enum. A string may instead throw a `TypeError`, which is not a predictable `PolicyDecision(False,...)`. This is an offline type-integrity defect, **not** a demonstrated real-target exploit or proof of end-to-end grant bypass.

## New offline contract

`tests/test_scope_773_direct_max_risk_expected_red_20261012.py` contains **15 in-memory tests**, of which **8 are intentionally expected RED** before the actual source-owner fix:
- Raw large integer, both bool identities, foreign high/same-value IntEnum, float, decimal and string scope-risk admissions.
- Canonical RiskLevel positive/negative controls, exact asset and capability isolation, existing client-binding and revocation precedence, and input immutability.
- Disposable hard-coded `.example.test` strings only; test code does not invoke any handler, DNS, sockets, HTTP or actual scan.
- Invalid cases use `@unittest.expectedFailure`, not implicit XFAIL acceptance: they must become normal passing denial tests after source-owner integration. Some failure paths may throw an exception; the required behavior is a deterministic fail-closed policy decision.

## Reproduction (not yet verified on an Actions runner)

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_773_direct_max_risk_expected_red_20261012.py' -v
```

**No run success is claimed.** This branch is deliberately **not opened as an extra PR** while the shared self-hosted queue is occupied by existing LightUp CI. It is a branch-only independent acceptance pack, not a released product fix. It does not modify `src/lightup/engagements.py`, `src/lightup/execution_policy.py`, domain issuance, active #100/#107 source, installed ingress, scripts or other-worker tests.

## Owner absorption and release gates

Owner #100 / complementary in-memory scope owner must validate `type(grant.scope.max_risk) is RiskLevel` in a trusted shared authorization boundary **before any comparison or handler** and preserve denial on unknown tenant, asset, capability, revocation and expiry. A validator returning a match on numeric values or coercing them to `RiskLevel` is not sufficient. Source owner should convert all expected RED to normal passing tests and run exact-head hosted Python 3.11/3.14 unit and real-producer tests, **separate registered permanent self-hosted LightUp CI**, independent security/privacy/tenant review, current-main compatibility and explicit human release authority. No live tests/grants/deploy.
