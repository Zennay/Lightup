# Legacy Authorization capability scope type acceptance

Tracking: #728  
Pinned source owner: draft PR #122 at `3554630323cf6a8625ac2a1856fb35b22516cdd9`

## Contract

The legacy `Authorization.capabilities` scope must use trusted built-in container
and entry types before membership is used as an authorization decision.

Required behavior:

- the container is an exact built-in `tuple`;
- every entry is an exact built-in `str`;
- a tuple subclass cannot override `__contains__` to mint arbitrary authority;
- a polymorphic string entry cannot carry one underlying capability while
  equality-spoofing another;
- canonical built-in tuple/string scope retains current behavior.

## Expected RED on the pinned source owner

PR #122 currently performs no runtime validation of the capability container or
its entries and implements membership as:

`return capability_id in self.capabilities`

Two acceptance methods are expected RED:

1. a tuple subclass with `__contains__ -> True` currently authorizes a foreign
   `api-baseline` request;
2. a stored `str` subclass carrying `ot-lab` can currently report equality with
   canonical `web-baseline` and mint that authority.

The exact built-in tuple + exact built-in string control remains green.

## Distinction from adjacent ownership

- #725 covers mutable caller-owned collection aliasing after Authorization creation.
- #726 covers the requested runtime capability ID at ActivationGate.
- #650 covers durable grant issuance capability identity.
- #576 covers the later target-active execution-request capability boundary.
- #122 retains all production source ownership.

This branch changes tests/documentation only.

## Safety

Authorization narrowing/integrity only. No capability handler is invoked; no
target interaction, DNS/network I/O, scanning, remediation/retest execution,
deployment, verdict creation or attack-path mutation occurs.
