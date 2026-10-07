# Passive-discovery admission integrity pack v6

Issue: #930  
Production owner: draft PR #175  
Base composition: #928 at `a84c2c404cef204fc933aca7d6b38cc23e37f7ff`

This branch composes seven fail-closed passive-discovery admission/provenance contracts without modifying production source:

- #915 — canonical built-in float confidence;
- #916 — exact outer `ProspectSignal` admission before caller-controlled validation;
- #921 — exact `SignalCategory` identity;
- #923 — exact, non-empty source provenance text;
- #925 — no constructor/list-mutation bypass around `add_signal()`;
- #927 — no whole-attribute signal collection replacement bypass;
- #929 — prospect identity cannot be rebound after signal admission.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- Earlier composition branches remain unchanged; v6 is a child composition only.
- This branch contains tests/docs acceptance evidence only.
- Admitted signal snapshots remain bound to their original prospect identity.
- Rejected mutation is never coerced, repaired or normalized into profile state.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 implementation until that owner absorbs the missing contracts.
