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
  child/suffix hosts such as `api.example.test`;
- exactly one terminal DNS root dot is removed; malformed multi-dot spellings
  such as `example.test..` remain distinct and cannot inherit authority.

## Implementation

The child repair branch centralizes durable asset canonicalization in
`ScopeDefinition._canonical_asset()`: surrounding whitespace is removed,
case is folded, and exactly one terminal DNS root dot is removed with
`removesuffix(".")`.

Allowlist entries, exclusions, and the caller-supplied asset all use that same
canonicalizer before membership is evaluated, so exclusions still win after
normalization.

## Collision boundary

This repair edits only `src/lightup/engagements.py` plus the dedicated #117
regression/doc paths. It does not edit `domain.py`, `scope.py`, activation,
execution policy, webapp, orchestration, or any target-capable source.

## Safety

Pure in-memory authorization comparison. No target interaction, DNS/network
I/O, scanning, exploit behavior, execution, remediation/retest, deployment,
verdict creation, or attack-path mutation.
