# Scope authorization: exact legacy Authorization type acceptance

Issue: #302

This tests/docs-only contract is stacked on exact PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

Public scope must not trust arbitrary caller objects merely because they expose
authorization-shaped methods and properties.

The regression supplies a duck-typed object with:

- `is_revoked = False`;
- `is_current() -> True`;
- `allows_asset() -> True`.

It must not authorize either an explicit public hostname or an explicit public
network. A canonical `models.Authorization` remains the positive control.

Expected RED on #100: `ScopePolicy.decide()` trusts the duck-typed surface and
both public decisions become allowed.

No `models.py`, `scope.py`, activation, domain, state, execution-policy or
target-capable source is modified. Source ownership remains with #100/#104 and
their stacked hardening.

Safety: authorization type/provenance narrowing only; no target interaction,
network I/O, scanning, execution, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
