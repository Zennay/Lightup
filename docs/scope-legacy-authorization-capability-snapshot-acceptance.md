# Legacy Authorization capability snapshot acceptance

Tracking: #725  
Pinned source owner: draft PR #122 at `3554630323cf6a8625ac2a1856fb35b22516cdd9`

## Contract

The capability scope attached to legacy `lightup.models.Authorization` must be a
snapshot of the authorization decision, not a live alias to caller-owned mutable
state.

Required behavior:

- an initially authorized capability remains authorized after the caller mutates
  or clears its original collection;
- a capability appended only after authorization creation remains unauthorized;
- the authorization stores/uses an immutable canonical capability tuple;
- exact tuple-based canonical scope keeps current behavior.

## Expected RED on the pinned source owner

PR #122 adds `Authorization.capabilities: tuple[str, ...]`, but the dataclass
annotation is not runtime enforcement and no constructor validation/snapshot is
performed.

Passing a caller-owned list therefore leaves the frozen Authorization object
pointing at the same mutable collection. Two acceptance methods are expected RED:

1. appending `api-baseline` after creation currently widens authority;
2. clearing the list after creation currently removes previously granted
   `web-baseline` authority.

The exact tuple control remains green.

## Distinction from adjacent ownership

- #300 covers legacy `Authorization.assets` snapshot integrity.
- #648 covers durable `ScopeDefinition` assets/exclusions/capabilities.
- #122 owns the production implementation for legacy capability binding and keeps
  `src/lightup/models.py` + `src/lightup/activation.py` ownership.

This branch is acceptance-only and deliberately changes no production source.

## Safety

Authorization narrowing/integrity only. No target interaction, DNS/network I/O,
scanning, exploit behavior, execution widening, remediation/retest execution,
deployment, verdict creation or attack-path mutation.
