# Session token identity boundary

Issue: #705

## Purpose

This acceptance slice proves that a caller-controlled Python object cannot borrow
the identity of a different live LightUp session merely by being a `str`
subclass with an overridden `encode()` method.

The durable session table stores only SHA-256 token hashes. The security
boundary therefore starts before hashing: the token object itself must have one
canonical identity.

## Required contract

- exact built-in `str` session tokens may be hashed and resolved;
- an ordinary forged string remains unauthenticated;
- a foreign `str` subclass cannot override `encode()` to hash as a live token;
- a `str` subclass is non-canonical even when its underlying text equals the
  canonical live token;
- rejecting a polymorphic lookup does not mutate the live session;
- rejecting a polymorphic revocation cannot delete the canonical live session.

A rejection may be represented either by an unauthenticated `None` result or
by a deterministic `TypeError`/`ValueError` at the direct domain boundary.
What is forbidden is successful resolution or mutation using a non-exact token
identity.

## Expected current result

At pinned parent `68318a318d828815bc50002114f64037ed06387e`
(PR #670), `DomainStore._token_hash()` calls `token.encode("utf-8")`
without exact-type validation. The encode-spoof lookup and revocation cases are
therefore expected RED.

## Collision boundary

This branch is tests/docs only. PR #670 keeps ownership of
`src/lightup/domain.py`. It does not modify web cookie parsing, duplicate
cookie handling (#686), redaction, target scope, execution policy, durable
grant resolution, or any target-interaction path.

## Safety

All tests use temporary SQLite, generated local credentials, and inert session
state. There is no network I/O, scanning, capability execution, remediation,
deployment, verdict generation, or attack-path mutation.
