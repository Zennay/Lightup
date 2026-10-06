# Explicit Unicode and IDNA host identities

LightUp treats the hostname spelling declared in scope policy as an authorization identity. Unicode hostnames and their IDNA/punycode aliases are therefore **not** implicitly interchangeable.

## Current invariant

Scope normalization may remove ordinary surrounding whitespace, fold case, and remove a terminal ASCII dot. It does not perform IDNA conversion or Unicode separator rewriting.

That means:

- `xn--bcher-kva.example` does not authorize `bücher.example`;
- `bücher.example` does not authorize `xn--bcher-kva.example`;
- case and a terminal ASCII dot remain equivalent within the same declared Unicode spelling;
- Unicode dot/lookalike separators do not inherit authority from an ASCII hostname;
- unknown Unicode hostnames remain out of scope.

## Why this is fail-closed

Automatically treating Unicode and punycode forms as equivalent would expand the set of identities accepted by an existing allowlist. Such canonicalization may be desirable later, but it must be introduced deliberately and consistently across every authorization boundary: allowed assets, exclusions, legacy authorization identities, durable grants, activation permits, and execution-policy asset binding.

Until that coordinated change exists, exact normalized identity is safer than incidental alias expansion.

## Regression contract

`tests/test_scope_idna_alias_boundary.py` proves the current conservative behavior entirely in memory. It performs no DNS lookup, socket operation, HTTP request, target interaction, scanning, execution, remediation/retest, deployment, or attack-path mutation.
