# Scope authorization: exact interaction + risk identity (opt-in)

**Issues:** [#986](https://github.com/Zennay/Lightup/issues/986), [#987](https://github.com/Zennay/Lightup/issues/987)  
**Phase:** Incubate, M3/M7 ST5, **PLAN/LAB ONLY**  
**Status:** DRAFT / HOLD / NO MERGE / NO DEPLOY

## Observed gap on main

`ExecutionPolicy.decide` checks the first three known `InteractionKind` members and otherwise falls into its TARGET_ACTIVE grant logic. A foreign interaction value can therefore be treated as active. The PASSIVE_PUBLIC path compares `requested_risk > RiskLevel.PASSIVE` without requiring a canonical RiskLevel; `True`, integral values and foreign IntEnums compare numerically. These are type-admission gaps, not independently proven production authorization bypasses.

## Isolated material implementation

- `src/lightup/scope_exact_identity_policy.py`: optional `StrictIdentityExecutionPolicy` subclass, refusing anything except **exact enum types** before delegating to the unchanged `ExecutionPolicy`. It does **not** normalize, coerce, approve, issue grants or interact with targets.
- `tests/test_scope_986_987_exact_identity_optin_20261012.py`: pure policy matrix and real `ToolExecutor` + `ToolRegistry` + disposable SQLite acceptance. Synthetic handlers return fixed evidence bytes and perform no I/O. Malformed tool metadata must be denied before handler and evidence write; valid canonical passive/active policy controls remain permitted only under inherited constraints.
- Production `src/lightup/execution_policy.py`, `src/lightup/ai/orchestration.py`, installed application, config, CI and all existing tests are **unchanged**. This opt-in module is deliberately **not wired into the default runtime**.

## Local reproduction / promotion requirements

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_986_987_exact_identity_optin_20261012.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_execution_policy.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_orchestration.py' -v
```

Treat the tests as **proposed acceptance** until actual exact-head raw CI records prove them. An offline green is **not** production enforcement. Before owner-gated integration, explicitly revalidate all interaction identity, risk ceiling, trusted issuer, tenant, engagement, asset, capability, authorization window, revocation and destination binding under current state. The original production owners of #100 / #107 must decide integration order with #986/#987 and any dependent stacked branches. No shared code change or ownership transfer is implied.

**Release gate:** exact final SHA hosted Python 3.11 and 3.14 unit + genuine producer integration; separate registered permanent VPS LightUp CI; independent security/privacy/source review and latest-main compatibility; explicit human approval. No real-client/target data, DNS, sockets, network testing, live grants, active scanning, merge or deploy from this draft.
