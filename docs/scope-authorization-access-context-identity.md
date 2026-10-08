# Scope authorization: canonical AccessContext identity

`AccessContext` is the identity boundary used by the durable domain layer for
tenant isolation and operator-only authorization decisions. It must therefore
fail closed before any authorization-sensitive method receives ambiguous audit
identity.

## Contract

- `user_id` is an exact built-in string, non-empty, already trimmed, and NUL-free.
- `role` is an actual `Role` member; raw strings and polymorphic substitutes
  are rejected.
- operator contexts carry no `client_id`.
- client contexts carry an exact built-in `client_id`, non-empty, already
  trimmed, and NUL-free.
- invalid contexts fail at construction and cannot reach grant, approval,
  revocation, finding, coverage, or other tenant-scoped domain operations.
- contexts reconstructed from durable user/session state pass the same constructor gate; corrupted persisted identity is rejected rather than normalized.
- authenticated session reconstruction treats missing or non-canonical durable user identity as an invalid session; corruption cannot escape as an authorization-bearing context or web-layer exception.
- caller-supplied tenant selectors passed to `resolve_client()` must also be exact canonical strings before operator selection or client-tenant comparison.
- `DomainStore.create_user()` accepts only an actual `Role` member and routes every client-bound user through the same canonical tenant-selector gate before persistence; forged role objects cannot mint operator identity.
- self-service password changes validate the supplied `user_id` as exact canonical text before owner equality is evaluated, so polymorphic string equality cannot redirect account authority.

## Safety boundary

This change only narrows authorization/provenance input. It does not add target
interaction, scanning, execution authority, risk elevation, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
