# Passive-discovery admission integrity pack v4

Issue: #926  
Production owner: draft PR #175  
Base composition: #924 at `c1c7cd6b89313974b2f58277950998651720e58c`

This branch composes five fail-closed passive-discovery admission contracts without modifying production source:

- #915 — confidence uses the canonical built-in float contract;
- #916 — profile admission receives an exact `ProspectSignal` before caller-controlled validation can run;
- #921 — signal category is an exact `SignalCategory` member;
- #923 — a public signal carries exact, non-empty source provenance text;
- #925 — callers cannot bypass `add_signal()` through constructor pre-seeding or a mutable public signal collection.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- #917, #922 and #924 remain unchanged; v4 is a child composition only.
- The branch contains tests/docs acceptance evidence only.
- Rejected input is never coerced, repaired, normalized or admitted.
- Rejection happens before destination profile mutation.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 implementation until that owner absorbs the missing contracts.
