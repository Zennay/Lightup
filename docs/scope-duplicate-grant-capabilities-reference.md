# Scope grant capability declaration uniqueness — offline reference

Status: **reference only, no production authority**. This contract supplies negative
acceptance cases for M7/ST5. It neither issues a grant nor dispatches a capability.

## Boundary

An incoming grant's capability declaration must be a finite, nonempty, exact tuple
of canonical identifiers. Duplicate declarations, wildcard IDs, unknown IDs,
case/whitespace/Unicode aliases, control characters and non-string elements
must fail closed rather than being silently deduplicated, normalized, coerced
or interpreted as a larger authority set.

Canonical membership is defined by an independently provisioned registry;
this reference fixture uses two illustrative identifiers only. The reference
does **not** authenticate that registry or issuer, bind a signature, enforce a
timestamp, detect revocation or prove tenant/request authorization. A positive
result is strictly syntax/shape eligibility, never permission to test a target.

## Acceptance for production owner

- Reject duplicate capability declarations at untrusted intake before making
  a set or writing an authorization record; never normalize duplicates away.
- Use registry-owned exact identifiers; do not infer authorization from string
  prefix, glob, casefold or user-provided aliases.
- Enforce source-owned byte/count ceilings before materializing large arrays;
  this small test fixture is not a resource-budget policy.
- Re-evaluate issuer lineage, tenant, grant revision, asset scope, capability,
  time window, revocation and risk at scheduling **and** each dispatch.
- On rejection, perform no grant write, queue append, target interaction,
  evidence emission or live capability execution.

## Reproduction

Run offline only:

```sh
python -m unittest discover -s tests -p test_scope_duplicate_grant_capabilities_reference.py -v
```

This test is intentionally pure Python standard library with no network,
filesystem writes, credentials, targets or production executor imports.
Owner of the production executor remains PR #107. Review and exact-head
hosted + canonical permanent VPS tests are required before integration.
