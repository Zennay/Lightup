# Durable grant time-integrity acceptance pack

Tracked by #736.

## Pinned source owner

This pack is based directly on draft PR #100 exact head:

`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

PR #100 retains all production ownership for `AuthorizationGrant.is_current()`.

## Included contracts

- #347 — canonical time-window semantics;
- #734 — exact built-in explicit evaluation datetime identity;
- #735 — explicit falsy evaluation-time input must not be treated as omission.

## Expected partition on the pinned source

Expected GREEN:
- all #347 time-window methods;
- #734 exact built-in inclusive-boundary control;
- #735 `None` omission control;
- #735 exact built-in aware-datetime control.

Expected RED:
- exactly 2 #734 datetime-subclass methods;
- exactly 3 #735 falsy-input methods.

No unexpected errors are part of the acceptance contract.

## Owner-side repair guidance

Keep the source repair inside PR #100:

1. distinguish `now is None` from an explicitly supplied value;
2. before `tzinfo` access or rich comparison, require `type(now) is datetime`;
3. keep exact built-in aware datetime comparison inclusive at both boundaries;
4. preserve existing revocation behavior;
5. do not normalize malformed caller input into a different evaluation instant.

#647 remains the separate durable issuance/persistence datetime owner.

## Safety and collision boundary

This pack adds tests/docs only. It does not modify production source, domain resolution, execution policy, activation, orchestration, target-capable workers, evidence-remediation, deployment, verdict or attack-path state.

No target/network activity or capability execution is performed.
