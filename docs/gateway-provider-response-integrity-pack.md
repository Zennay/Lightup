# Gateway provider-response integrity acceptance pack

Issue: #788  
Source-owner parent: #574 `3ae92d599832220598118b277383e3c667804287`  
Composition base: #786 `e1c24b3045a3026f5b63e41b5765f679eacb9743`

## Included contracts

1. #786 — `ModelResponse.content` must be exact built-in `str` before
   downstream consumers can invoke provider-controlled string behavior.
2. #787 — provider return value must be exact `ModelResponse`; duck-typed
   objects and subclasses fail closed.
3. #795 — returned role must be the exact requested `ModelRole`; a different
   enum member or a plain string role fails closed.

The exact canonical response remains the shared green control.

## Expected state before source absorption

All provider-return hardening contracts are intentionally RED on #574
source. This pack changes no production code and makes no green claim. It is a
single preferred reproof head for the source owner after the narrow gateway
guards are absorbed.

## Existing shared gateway invariants retained

- #570 exact response provider identity;
- #572 exact response model identity;
- #574 bounded canonical configured identities;
- role routing remains provider-neutral and unchanged.

## Stop line

No remediation producer source, scope authorization, target interaction,
scanning, tool execution, remediation/retest execution, deployment, security
verdict or attack-path mutation is included.
