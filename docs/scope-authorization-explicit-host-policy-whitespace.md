# Explicit-host policy whitespace is not authority

Issue: #368

## Contract

`ScopePolicy.explicit_hosts` is an exact policy-side host-identity allowlist. Surrounding whitespace in stored policy text is not silently trimmed into a valid host identity.

A policy entry therefore does **not** grant authority merely because a valid hostname appears after removing:

- leading spaces;
- trailing spaces;
- leading tabs;
- trailing newlines; or
- mixed surrounding whitespace.

This is a fail-closed configuration boundary. Automatically cleaning malformed policy text inside the scope decision primitive could convert configuration that was not explicitly declared as a host identity into new public-target authority.

## Target-side behavior

This contract does not change the existing target parser. Surrounding whitespace on a target value may still be removed by `ScopePolicy.normalize_host()` before the target identity is evaluated.

The distinction is intentional:

- target input is normalized into an identity before matching;
- policy configuration must already express the intended host identity.

## Positive control

A plain host policy entry retains the existing canonical match behavior for case folding and a terminal DNS dot.

## Boundaries

This contract is separate from #367, which keeps URL-like policy entries non-authoritative; #286, which owns wildcard/suffix behavior; and #366, which owns percent-encoded host identity behavior.

The regression is pure and in-memory. It does not perform DNS resolution, socket/HTTP I/O, scanning, capability execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
