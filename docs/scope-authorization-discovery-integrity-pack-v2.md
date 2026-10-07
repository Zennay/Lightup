# Passive-discovery admission integrity pack v2

Issue: #922  
Production owner: draft PR #175  
Base composition: #917 at `7d51ee300665ec9a775c45337d08a02a42f0b566`

This branch composes three independent fail-closed admission contracts without modifying production source:

- #915 — confidence must use the canonical built-in float contract;
- #916 — profile admission must receive an exact `ProspectSignal` object before caller-controlled validation runs;
- #921 — signal category must be an exact `SignalCategory` member before profile mutation.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- #917 remains unchanged; v2 is a child composition only.
- The branch contains tests/docs acceptance evidence only.
- No input is coerced, repaired, normalized, deduplicated, or widened to satisfy admission.
- Every rejected input must leave the destination profile unchanged.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment, or authorization widening is allowed.

The pack is intentionally expected RED against the pinned #175 production implementation until that owner absorbs the missing contracts.
