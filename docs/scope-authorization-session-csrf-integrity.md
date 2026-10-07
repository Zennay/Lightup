# Durable session CSRF-secret integrity

Issue: #708

## Purpose

A server-side session is only authorization-bearing when both its session token
and its CSRF secret remain canonical. The web dispatcher accepts an
authenticated POST only when the submitted form CSRF value equals the secret
returned by `DomainStore.session_context()`.

The durable `csrf_token` column must therefore be revalidated before the
session becomes authenticated.

## Issuance contract

`create_session()` uses `secrets.token_urlsafe(32)`. For the current product
contract this produces an exact built-in string containing 43 unpadded
URL-safe Base64 characters:

`[A-Za-z0-9_-]{43}`

A generated canonical session is the green control.

## Fail-closed contract

Session resolution must return unauthenticated state when durable CSRF state is:

- empty;
- shorter or otherwise non-canonical in length;
- surrounded by whitespace;
- built from characters outside the URL-safe alphabet;
- stored as a non-text SQLite value such as BLOB bytes.

Rejected rows remain byte/value-equivalent in storage so corruption is not
silently normalized into authority and forensic evidence is retained.

## Expected current result

At pinned parent `68318a318d828815bc50002114f64037ed06387e`
(PR #670), `DomainStore.session_context()` selects `csrf_token` and returns
it directly after the session token/expiry checks. It performs no type, shape,
length, or syntax validation. The corruption cases are therefore intentionally
expected RED until the active domain source owner absorbs this boundary.

## Collision boundary

Tests/docs only. No `src/lightup/**` edits.

Distinct ownership remains with:

- #705 exact session-token identity;
- #706 durable session temporal integrity;
- #686 duplicate cookie ambiguity;
- #670 access/account/session reconstruction source;
- web request/form source owners and all target-capable lanes.

## Safety

Temporary SQLite and locally generated session state only. No network I/O,
target interaction, scanning, capability execution, remediation/retest,
deployment, verdict generation, or attack-path mutation.
