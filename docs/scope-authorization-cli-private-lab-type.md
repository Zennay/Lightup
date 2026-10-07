# CLI private-lab marker type integrity

Issue: #905

This acceptance contract is pinned directly above active PR #100 exact head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Problem

PR #100 correctly changes the ordinary CLI default so broad private-address trust
requires explicit opt-in. Its helper currently constructs the policy with:

`allow_private_lab=bool(args.allow_private_lab)`

That is safe for a namespace produced by argparse itself, but the helper is also
a callable configuration boundary. A direct/programmatic namespace can carry a
truthy non-boolean value such as `"false"` or `1`. Python coercion turns that
malformed input into exact `True`, so a later exact-boolean `ScopePolicy`
guard can no longer distinguish the original caller value.

## Required invariant

Before `ScopePolicy` construction:

- `allow_private_lab` must be an exact built-in `bool`;
- exact `False` keeps ordinary private IPs out of scope;
- exact `True` remains the explicit private-lab opt-in;
- truthy strings, integers and arbitrary boolean-like objects fail closed;
- malformed values are not coerced into authorization state;
- caller-owned namespace values remain unchanged.

This is a caller-boundary complement to #164/#165, not a replacement for the
lower-level ScopePolicy boolean contract.

## Collision boundary

This branch adds tests and documentation only. PR #100 retains production
ownership of `src/lightup/cli.py` and `src/lightup/scope.py`.

It does not modify domain, activation, execution policy, web authorization,
target-capable workers, evidence-remediation, remediation/retest execution,
deployment, security-verdict authority or attack-path state.

## Safety

Offline configuration validation only. No DNS/network I/O or target
interaction occurs.
