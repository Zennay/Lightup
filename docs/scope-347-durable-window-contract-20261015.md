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

## W2: DST fall-back same-zone fold regression (owner source RED)

The original source comparison also has a **real precision hazard**, separate from the 16 green W1 tests. Python's aware `datetime` ordering with the **same `ZoneInfo` instance** compares equal local wall times without distinguishing `fold=0` from `fold=1` during an autumn DST fall-back. Those instants are *one hour apart in UTC*. On a direct durable grant, this can mean an evaluation **before valid_from** or **after valid_until** is incorrectly reported current.

Four additional methods use the fictional `America/New_York` fall-back of 2030-11-03 (no real permission and no I/O):
- Two genuine `@expectedFailure` tests require deny-before-start and deny-after-expiry but expose the installed source's current permissive result. These **are not source fixes**; a hosted success with two expected failures is still an unsafe authorization behavior.
- A regular passing witness independently checks UTC chronology, fold-specific offsets, Python's local comparison, and the current implementation returning unauthorized `True` in both cases. A missing `ZoneInfo` database or unexpected runtime error cannot silently masquerade as expected-RED.
- A regular passing UTC-control test proves converting both grant bounds and evaluation time to UTC denies those same chronological violations.

**W2 now contains 20 methods: 18 ordinary passing expected behaviors / witness methods and 2 deliberately expected source REDs.** The 16/16 W1 source-backed passes were verified at superseded exact HEAD `261db806bb59f95d9a463ea368b91949932bbc8b`, not W2. New W2 immutable-head CI must be checked independently. Owner of `src/lightup/engagements.py` and #647/#738 datetime identity gates must address the actual UTC-chronological comparison invariant without widening authority. No source or owner branch is edited here, and any real user consent, revocation, runner, integration, security/privacy and human release remains blocked.

The whole suite on W1 failed **one separate pre-existing #301 real-wall-clock fixture** on both Python interpreters; that failure is unrelated to these DST tests and must remain visible. DO NOT promote a green expected-RED test into a fixed-source claim.
