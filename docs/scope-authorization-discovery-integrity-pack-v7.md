# Passive-discovery admission integrity pack v7

Issue: #932  
Production owner: draft PR #175  
Base composition: #930 at `923939c59a5d49fee2b148474f1f9ae402c2b8d7`

This branch composes eight fail-closed passive-discovery admission/provenance contracts without modifying production source:

- #915 — canonical built-in float confidence;
- #916 — exact outer `ProspectSignal` admission before caller-controlled validation;
- #921 — exact `SignalCategory` identity;
- #923 — exact, non-empty source provenance text;
- #925 — no constructor/list-mutation bypass around `add_signal()`;
- #927 — no whole-attribute signal collection replacement bypass;
- #929 — prospect identity cannot be rebound after signal admission;
- #931 — prospect identity fields are exact non-empty built-in text at construction.

## Composition invariants

- `src/lightup/discovery.py` remains owned by PR #175.
- Earlier composition branches remain unchanged; v7 is a child composition only.
- This branch contains tests/docs acceptance evidence only.
- Malformed identity fails before any signal admission.
- Rejected input/mutation is never coerced, repaired or normalized into profile state.
- No active discovery, DNS/network I/O, target interaction, capability execution, remediation/retest execution, deployment or authorization widening is allowed.

The pack is intentionally expected RED against the pinned PR #175 implementation until that owner absorbs the missing contracts.
