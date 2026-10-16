# Scope replay matrix #344 — independently seeded offline source tests

**LightUp INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.** The matrix is an additive source-integrated TEST ONLY, not an active feature, scan, permit, grant, revocation check or release decision.

## Why this second acceptance suite

The initial 14 checks establish input purity and 32x same-request replay for selected scenarios. The new independent test file `tests/test_scope_repeatability_matrix_344_20261016.py` extends that to an orthogonal Cartesian batch of **96 scenarios** across four immutable policies, eight fictitious/lexical target values, and three authorization states. It uses seeded local `Random(344)` shuffles to inspect replay-order cross contamination, not real-world randomness or network I/O.

## Concrete safety expectations

- 96 scenarios x 32 repeated evaluations remain equal to their first actual `ScopePolicy.decide` result.
- 64 shuffled ordering cycles over the same exact instances cannot change results or their input snapshots.
- Positive and negative canaries independently check actual reason and `allowed` type, preventing a vacuous pass where every input is denied.
- Alternating allowed, expired and nonmember public host decisions cannot leak earlier authorization state.
- Case-normalized canonical public input yields equal results but never overwrites original caller text.
- Explicit host frozenset and network tuple remain intact; detached equal-value canonical objects produce equivalent decisions.
- Socket, DNS and subprocess calls are patched to raise during real in-process decision evaluation. No target is contacted.
- Decision record never contains an executable permit or activation reference; this is not sufficient live approval.

## Reproduce exact own suites

```bash
PYTHONPATH=src python -m unittest tests.test_scope_repeatability_input_purity_344_20261016 tests.test_scope_repeatability_matrix_344_20261016 -v
```

## Limitations and ownership

This is restricted to stable canonical **immutable** objects, controlled fictional labels and fixed grant windows (2020–2099 current; 2020–2021 expired). It does not establish deterministic behaviour at a moving grant-expiry boundary (time can legitimately change a decision), defend mutable external policy buffers (#294), replace source-owner repairs, validate actual customer grants or stop malformed target parsing (#1289). No original runtime, tests owned by other workers, existing workflows, or runner configurations changed. PR and project remain DRAFT/HOLD until independent owner/security review, genuine client/operator consent, durable revocation, permanent registered VPS CI and explicit human GO.
