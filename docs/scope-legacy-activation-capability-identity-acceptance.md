# Legacy activation capability identity acceptance

Tracking: #726  
Pinned source owner: draft PR #122 at `3554630323cf6a8625ac2a1856fb35b22516cdd9`

## Contract

The capability identity crossing `ActivationGate.issue()` in AUTHORIZED mode must
be an exact built-in string before capability membership is trusted or an
`ExecutionPermit` is created.

Required behavior:

- exact built-in allowlisted capability strings remain permitted;
- ordinary different built-in strings remain denied;
- a matching-text `str` subclass is rejected;
- a non-string object whose `__eq__` claims equality with an allowlisted
  capability is rejected;
- every successful permit contains an exact built-in `str` capability ID.

## Expected RED on the pinned source owner

PR #122 currently relies on the annotation `capability_id: str` and delegates to
ordinary tuple membership in `Authorization.allows_capability()`.

Two acceptance methods are expected RED:

1. a `str` subclass containing `web-baseline` currently passes ordinary string
   equality and can be stored in the permit;
2. a non-string equality-spoofing object can receive the reflected comparison
   after built-in string comparison returns `NotImplemented`, claim equality
   with `web-baseline`, and cross the same boundary.

The exact canonical allowlisted control and ordinary foreign-string denial remain
green.

## Distinction from adjacent ownership

- #725 covers mutable caller-owned capability collections after Authorization creation.
- #576 covers target-active `ExecutionRequest.capability_id` at the later
  execution-policy boundary.
- #122 retains all production ownership for legacy capability binding.

This branch changes tests/documentation only.

## Safety

Authorization narrowing/integrity only. Permit construction is in-memory; no
capability handler is invoked and no target interaction, DNS/network I/O,
scanning, remediation/retest execution, deployment, verdict creation or
attack-path mutation occurs.
