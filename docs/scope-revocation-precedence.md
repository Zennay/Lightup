# Scope authorization revocation precedence

Issue: #348  
Dependency: draft PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

Explicit revocation is a terminal authorization state. Once a target-level authorization has been revoked, later scope evaluation must not revive it because another predicate would otherwise pass.

The scope gate therefore preserves this order for public targets already present in an explicit host or network allowlist:

1. authorization must exist;
2. explicit revocation denies immediately;
3. an unrevoked authorization must still be current;
4. an unrevoked, current authorization must still be bound to the normalized target asset;
5. only then may the explicit host/network route allow the target.

This ordering is intentional. Revocation represents withdrawal of previously granted authority, so expiry state or asset metadata must not mask or supersede that withdrawal in a way that could later be misinterpreted as reusable authority.

## Regression proof

`tests/test_scope_revocation_precedence.py` proves, without network I/O, that:

- a revoked authorization inside an otherwise-current time window is denied;
- a revoked authorization that is also expired still reports `authorization_revoked`;
- explicit-host and explicit-network paths enforce the same terminal denial;
- a revoked authorization with mismatched asset metadata is still terminally revoked;
- a non-revoked expired authorization continues to report `authorization_expired`, so the rule is specific to revocation rather than a generic failure rewrite.

## Safety boundary

This package is proof-only. It adds no target adapter, request, DNS lookup, socket use, capability execution, remediation/retest execution, deployment action, verdict creation, or attack-path mutation. It does not modify the production implementation owned by PR #100.

A green result means only that the existing #100 semantics remain fail-closed under these overlapping authorization states. It does not activate real-target execution.
