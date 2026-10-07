# Passive-discovery admission integrity pack v5

Issue: #928  
Production owner: draft PR #175  
Base composition: #926 at `bae29786f65353d217ecb7692cad6e29112d689a`

This branch composes six fail-closed passive-discovery admission contracts without modifying production source:

- #915 — confidence uses the canonical built-in float contract;
- #916 — profile admission receives an exact `ProspectSignal` before caller-controlled validation can run;
- #921 — signal category is an exact `SignalCategory` member;
- #923 — a public signal carries exact, non-empty source provenance text;
- #925 — callers cannot bypass `add_signal()` through constructor pre-seeding or mutable collection methods;
- #927 — callers cannot replace the whole admitted signal collection after construction.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- Earlier composition branches remain unchanged; v5 is a child composition only.
- The branch contains tests/docs acceptance evidence only.
- `add_signal()` is the only public signal-admission mutation path.
- Rejected input/replacement is never coerced, repaired, normalized or admitted.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 implementation until that owner absorbs the missing contracts.
