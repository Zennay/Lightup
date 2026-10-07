# Passive-discovery admission integrity pack v3

Issue: #924  
Production owner: draft PR #175  
Base composition: #922 at `b5781a26be5e6c6ea31cd0e4e0984100d547c99a`

This branch composes four independent fail-closed admission contracts without modifying production source:

- #915 — confidence uses the canonical built-in float contract;
- #916 — profile admission receives an exact `ProspectSignal` before caller-controlled validation can run;
- #921 — signal category is an exact `SignalCategory` member;
- #923 — a public passive-discovery signal carries exact, non-empty source provenance text.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- #917 and #922 remain unchanged; v3 is a child composition only.
- The branch contains tests/docs acceptance evidence only.
- Rejected input is never coerced, repaired, normalized or admitted.
- Rejection happens before destination profile mutation.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 source until that owner absorbs the missing contracts.
