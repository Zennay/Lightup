# Scope authorization: unknown interaction kind — RED contract

**Status:** intentionally failing regression until the production policy owner accepts a fail-closed fix.

## Reproduction

Run offline with `PYTHONPATH=src python -m unittest tests.test_scope_unknown_interaction_red -v`.
The synthetic grant, `.invalid` hostname and capability are fixtures only; no adapter, HTTP, DNS or real target is contacted.

In `ExecutionPolicy.decide`, only the four recognized `InteractionKind` values should be considered. Current dispatch branches explicitly cover ANALYSIS, PASSIVE_PUBLIC and LAB_ACTIVE, then implicitly assume everything else is TARGET_ACTIVE. A string typo such as `"target_actve"` can therefore be approved if the caller supplies a valid grant, authorized asset and capability. That decision is not acceptable; unknown, string-based and other non-enum kinds must fail closed *before* grant evaluation.

## Acceptance contract for the production owner

- Only exact `InteractionKind` members are admitted; malformed input must return a denied decision without side effects.
- Genuine `InteractionKind.TARGET_ACTIVE` continues to follow durable grant, scope, risk and pre-I/O revocation controls.
- No caller, model, JSON payload or custom string subclass may implicitly select TARGET_ACTIVE.
- This regression remains a **RED** contract until owner integration; do not mark as green, merge to main or activate real targets on this evidence alone.
- Keep executor dispatch, persisted authorization, destination binding, revocation and release decisions with their existing owners.

## Files changed

Only an isolated new offline regression test and this documentation. Production source is intentionally unchanged to avoid crossing the parallel worker ownership boundary.
