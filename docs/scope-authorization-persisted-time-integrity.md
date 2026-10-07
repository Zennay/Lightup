# Persisted grant temporal integrity

Issue: #470  
Parent source owner: PR #142  
Exact parent head: `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Purpose

The target-active execution resolver already re-reads durable authorization and revalidates risk/capability safety. This acceptance slice adds one independent requirement: persisted authorization timestamps must also fail closed when durable state is malformed or timezone-ambiguous.

## Contract

The execution resolver may return a grant only when its persisted temporal state is structurally safe.

- `valid_from` and `valid_until` must parse as timezone-aware datetimes.
- Malformed timestamps are non-executable.
- Offsetless timestamps are non-executable; the resolver must not infer UTC.
- A malformed or offsetless `revoked_at` value is non-executable.
- Revalidation must not rewrite or normalize the persisted row as a side effect.
- A canonical, current, timezone-aware grant must keep resolving normally.

The intended execution-plane result for invalid persisted temporal state is `None`, not an exception and never an authorization object.

## Expected-red acceptance proof

`tests/test_scope_authorization_persisted_time_integrity.py` contains one green canonical control and three corruption cases. On the exact #142 source head, the corruption cases are expected to expose the missing temporal fail-closed boundary:

1. offsetless `valid_from`;
2. malformed `valid_until`;
3. offsetless `revoked_at`.

The source-owner repair belongs in #142's domain execution-resolution boundary. This child must remain tests/docs-only.

## Safety boundary

This work only narrows authorization interpretation. It adds no target interaction, scanning, exploit behavior, execution widening, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
