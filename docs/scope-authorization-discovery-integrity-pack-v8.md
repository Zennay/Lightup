# Passive-discovery admission integrity pack v8

Issue: #934  
Production owner: draft PR #175  
Base composition: #932 at `a00f354fc9f9347e6e2e088f507a2f4c93683013`

This branch composes nine fail-closed passive-discovery admission/provenance contracts without modifying production source:

- #915 — canonical built-in float confidence;
- #916 — exact outer `ProspectSignal` admission before caller-controlled validation;
- #921 — exact `SignalCategory` identity;
- #923 — exact, non-empty source provenance text;
- #925 — no constructor/list-mutation bypass around `add_signal()`;
- #927 — no whole-attribute signal collection replacement bypass;
- #929 — prospect identity cannot be rebound after signal admission;
- #931 — prospect identity fields are exact non-empty built-in text at construction;
- #933 — signal summary is exact non-empty built-in text before admission.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- Earlier composition branches remain unchanged; v8 is a child composition only.
- This branch contains tests/docs acceptance evidence only.
- Composition-layer snapshot assertions are canonicalized to exact tuples across all inherited tests; standalone child branches remain unchanged.
- Malformed identity/summary fails before signal admission or profile mutation.
- Rejected input/mutation is never coerced, repaired or normalized into trusted profile state.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 implementation until that owner absorbs the missing contracts.
