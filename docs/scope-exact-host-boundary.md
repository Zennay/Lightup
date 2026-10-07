# Exact explicit-host authorization boundary

`ScopePolicy.explicit_hosts` is an exact normalized host-identity allowlist. It is not a DNS suffix policy and it does not implement wildcard inheritance.

## Invariant

- authorizing `example.test` does not authorize `api.example.test`;
- `*.example.test` is literal policy text and does not authorize `api.example.test`;
- `.example.test` does not authorize child hosts;
- a suffix lookalike such as `security.example.test.attacker.test` does not inherit authority from `security.example.test`;
- the exact declared host continues to use the existing case-folding and terminal-ASCII-dot normalization.

## Why exact matching matters

A scope allowlist is an authorization boundary, not a routing convenience. Implicit wildcard, parent-domain, public-suffix, or registrable-domain semantics would enlarge an existing grant without a new authorization decision. If wildcard scope is ever added, it must be a separate explicit policy type with its own review, exclusions, persistence, activation, and execution-policy semantics.

## Regression contract

`tests/test_scope_exact_host_boundary.py` proves these rules entirely in memory. It performs no DNS resolution, socket or HTTP operation, target interaction, scanning, execution, remediation/retest, deployment, or attack-path mutation.
