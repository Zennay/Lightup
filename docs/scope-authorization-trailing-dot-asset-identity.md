# Durable asset trailing-dot identity

Issue: #117

## Purpose

DNS names with and without one terminal dot identify the same host. Durable
authorization must not let the spelling difference separate the allowlist from
its exclusions.

## Required contract

`ScopeDefinition.allows_asset()` must compare canonical DNS identities such
that:

- `example.test` and `example.test.` are equivalent;
- the equivalence applies in both directions between caller and stored scope;
- exclusions are canonicalized by the same rule and continue to win;
- existing case-folding and surrounding-whitespace normalization remains;
- exact scope stays exact: canonicalizing the terminal dot must not authorize
  child/suffix hosts such as `api.example.test`.

## Expected current result

Exact current `main` normalizes durable scope entries with only
`strip().lower()`. It does not remove a single terminal DNS dot. The four
equivalence/exclusion cases are therefore expected RED while the existing
case/whitespace and unrelated-host controls remain green.

## Collision boundary

This branch is tests/docs only. It does not edit
`src/lightup/engagements.py`, `domain.py`, `scope.py`, activation,
execution policy, webapp, orchestration, or any target-capable source.

The production repair belongs to the existing durable asset-identity source
owner; this branch only defines the acceptance boundary for #117.

## Safety

Pure in-memory authorization comparison. No target interaction, DNS/network
I/O, scanning, exploit behavior, execution, remediation/retest, deployment,
verdict creation, or attack-path mutation.
