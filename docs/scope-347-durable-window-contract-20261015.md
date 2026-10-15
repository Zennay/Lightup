# #347 — deterministic durable grant time-window acceptance

## Purpose and source boundary

This tests-only acceptance slice verifies the **currently installed** `AuthorizationGrant.is_current()` from `src/lightup/engagements.py` without changing that class, the persisted domain store, any execution adapter, active scan capability or another worker branch.

Pinned parent: `main` `e73b7445c87ad239bdb03c50a99078ef93163b02` (15 October 2026). The source owner retains all rights to fix behavior; this branch owns only two new paths: this document and `tests/test_scope_347_durable_window_contract_20261015.py`.

## Invariants proven only within a deterministic fictional domain

The 16 independent standard-library unittest methods cover:

- Inclusive `valid_from` and `valid_until`, midpoint, exact microsecond before and after expiry.
- Equivalent instants under UTC+05:30, UTC-07:00 and a UTC+09:00 grant; six legal offsets crossed with nine instant positions (54 separately named subtests).
- A timezone-naive evaluation instant fails with `ValueError` instead of acquiring authority.
- A directly constructed inverted window is never current at seven sampled instants.
- A zero-length grant is valid only at exactly its single authorized instant.
- Moving the grant window to the future cannot inherit its prior authority.
- Pure evaluation does not mutate identity, scope, approval provenance, grant dates or flags.
- Frozen grant fields cannot be reassigned through ordinary instance assignment.
- Two separate grant objects retain independent window decisions.

All instants are fixed around 2030-01-02, so tests remain meaningful regardless of the real wall clock and will not create a repeat of #301's expired fixture. All identifiers use fabricated `fictional-*` values; `offline.invalid` is only an inert string, never resolved.

## Reproduce / interpretation

```sh
python -m unittest -v tests/test_scope_347_durable_window_contract_20261015.py
```

CI should run these with the installed project on Python 3.11 and 3.14, plus the real producer integration suite, and inspect original job logs at **the exact immutable branch HEAD**. A test suite that is green on this narrow temporal contract does **not** establish safety of issuance, persisted consent, live revocation, handler admission, privacy, customer ownership, egress, registered VPS execution or security release.

If a source regression is seen, report the precise method/expected behavior back to #347 and the owning source team. Never silently convert a genuine source regression to an expected failure or suppress an unrelated CI failure.

## Hard STOP line

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This branch contains tests and documentation only. No real grant, target scan, network I/O, customer data, handler execution, activation, deployment or merge. Release requires owner-reviewed integrated source fixes, exact-head hosted and permanently registered VPS CI, independent security/privacy checks, real customer/operator consent and explicit human GO.
