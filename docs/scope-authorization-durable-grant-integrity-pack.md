# Durable grant in-memory integrity acceptance pack

Tracked by #739.

## Pinned source owner

This successor pack is based on #736 and therefore remains pinned to draft PR #100 exact head:

`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

PR #100 retains all production ownership for `AuthorizationGrant.is_current()`.

## Included contracts

- #347 — canonical time-window semantics;
- #734 — exact built-in explicit evaluation datetime;
- #735 — falsy explicit evaluation inputs fail closed;
- #737 — stale revocation provenance fails closed;
- #738 — exact built-in stored validity datetime boundaries.

## Expected partition on the pinned source

Expected RED total: **10**.

- #734: 2 evaluation-datetime subtype cases;
- #735: 3 falsy-input cases;
- #737: 3 stale-revocation-provenance cases;
- #738: 2 stored-datetime subtype cases.

All #347 methods and all canonical controls in the four hardening slices are expected GREEN. No unexpected errors are accepted.

## Owner-side repair guidance

Keep the repair inside PR #100:

1. distinguish `now is None` from explicitly supplied input;
2. require exact built-in aware `datetime` for explicit evaluation instants;
3. require exact built-in aware `datetime` for stored `valid_from` / `valid_until`;
4. fail closed on revocation actor/reason provenance without `revoked_at`;
5. preserve canonical inclusive window semantics and canonical revocation behavior;
6. reject rather than normalize malformed authorization state.

#647 remains issuance/persistence datetime ownership. #560/#562 remain persisted revocation reconstruction/coherence.

## Safety and collision boundary

Tests/docs composition only. No production source, domain persistence/resolution, execution policy, activation, orchestration, target-capable workers, evidence-remediation, deployment, verdict or attack-path state is modified.

No target/network activity or capability execution is performed.
