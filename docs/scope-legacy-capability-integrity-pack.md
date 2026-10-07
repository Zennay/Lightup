# Legacy capability authorization integrity pack

Pinned source owner: draft PR #122 at
`3554630323cf6a8625ac2a1856fb35b22516cdd9`.

This successor pack composes collision-free acceptance contracts for the legacy
`Authorization.capabilities` + AUTHORIZED activation boundary without changing
production source.

Included issues:

- #725: capability scope is snapshotted immutably and cannot be widened/narrowed
  by later mutation of a caller-owned collection;
- #726: the requested activation capability identity must be an exact built-in
  string before membership is trusted or an ExecutionPermit is created.

## Expected partition

#725 contributes two expected-RED methods on exact #122:
- append-after-creation currently widens capability authority;
- clear-after-creation currently narrows the already-created authorization.

#726 contributes two expected-RED methods:
- matching-text `str` subclass currently crosses ordinary equality;
- non-string equality-spoofing object can claim allowlisted membership.

Canonical exact-tuple scope, exact allowlisted built-in capability, and ordinary
foreign built-in capability denial remain green controls.

Combined expected acceptance RED count: **4 test methods**.

## Ownership and stop line

This branch is tests/docs only. PR #122 retains
`src/lightup/models.py` and `src/lightup/activation.py` production ownership.
It does not modify durable grants/ScopeDefinition, execution policy, webapp,
target-capable workers, remediation/retest, deployment, verdict or attack-path
code.

No capability handler is invoked; permit construction is in-memory only.
