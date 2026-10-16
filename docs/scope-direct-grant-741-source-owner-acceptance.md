# #741 — direct ExecutionPolicy grant identity acceptance

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is an
additive tests/docs/CI source-owner contract based on [PR #100](https://github.com/Zennay/Lightup/pull/100)
exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.
It does **not** modify `execution_policy.py`, `engagements.py`,
the executor, the registry, authorization issuance, live resolution, or any
other worker's branch.

## Reproduced installed-source boundary

At the direct `ExecutionPolicy.decide` TARGET_ACTIVE path, the supplied
`ExecutionRequest.authorization` is annotated as an `AuthorizationGrant`
but not checked for exact runtime object identity. The policy invokes
`grant.is_current()` and then trusts canonical-looking scope/lineage
fields. A directly constructed `AuthorizationGrant` subclass can return
`True` for an expired grant. A duck object exposing the same methods
can also counterfeit validity. These are **synthetic in-memory policy
acceptance gaps**; they are not proof of a live dispatched handler or
authenticated consent.

## Source owner repair contract

1. At the TARGET_ACTIVE policy boundary, reject any present authorization
   whose runtime `type(grant) is not AuthorizationGrant`, before invoking
   `grant.is_current()`, traversing scope or considering authority.
2. Deny missing/non-canonical objects deterministically, without
   invoking user-supplied `is_current` or coercing objects.
3. Preserve exact canonical currently valid grants, expired grants,
   revocation checks, tenant/engagement lineage and scope requirements.
4. Preserve request/grant objects on denial. No mutation of real
   grants, target handlers, network, scans or other risk-bearing effects.
5. Keep nested scope object validation assigned to #740, stored validity
   timestamp validation assigned to #738, and durable resolver/dispatch
   assigned to #106; this issue is solely the **outer direct grant type**.

## Test acceptance

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_direct_grant_identity_741.py' -v
```

The suite contains seven ordinary canonical controls and **two deliberate
source-owner expected-REDs** (`@unittest.expectedFailure`) exercising
subclass and duck polymorphism. A green diagnostic CI with two expected
failures is **not** a fixed authority boundary. Source owner must remove
those decorators after product repair and require all nine tests as
ordinary PASS on Python 3.11 and 3.14, in addition to the normal full
product and named registered permanent VPS tests.

## Release/HOLD

The isolated hosted matrix contains no real asset, secret, consent, DNS,
scan, grant issuance or handler invocation. Keep this PR DRAFT/HOLD.
No merge, deploy, release or execution authority follows from these
tests. Verified independent client and operator consent, at-use
revocation, security/privacy review, exact-head whole-project hosted and
genuinely registered permanent `vps-bb300bba` green, and explicit
human GO remain mandatory.
