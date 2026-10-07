# Durable session temporal integrity

Issue: #706

## Purpose

A persisted session is authorization-bearing state. Resolving it must therefore
revalidate the temporal invariants established when the session was issued,
rather than trusting arbitrary durable text.

## Required contract

A canonical session remains resolvable when all of these hold:

- `created_at` and `expires_at` are timezone-aware canonical datetimes;
- `created_at <= now < expires_at`;
- `expires_at > created_at`;
- `expires_at - created_at <= 30 days`.

Durable corruption must fail closed to unauthenticated state. In particular:

- malformed or naive expiry text cannot raise through the auth boundary;
- a future creation time cannot authenticate;
- an overlong persisted lifetime cannot extend authority beyond the issuance
  maximum;
- an inverted creation/expiry interval cannot be normalized into authority.

For corrupt rows, rejection is read-only. The row is preserved unchanged for
forensic inspection instead of being silently repaired or rewritten.

## Expected current result

At pinned parent `68318a318d828815bc50002114f64037ed06387e`
(PR #670), `DomainStore.session_context()` reads only `expires_at`,
parses it without a corruption guard, and compares it directly to `utcnow()`.

Therefore:

- malformed expiry can raise `ValueError`;
- naive expiry can raise `TypeError`;
- future `created_at` is ignored;
- persisted lifetime longer than 30 days can authenticate;
- already-expired inverted rows are currently deleted as ordinary expiry rather
  than treated as corrupt forensic state.

These are intentionally expected-RED acceptance cases until the active domain
source owner absorbs the boundary.

## Collision boundary

Tests/docs only, stacked on exact #670 head. No edits to
`src/lightup/domain.py`.

Separate ownership remains with:

- #705 session token exact-identity acceptance;
- #686 duplicate-cookie ambiguity;
- #670 access/account identity source;
- redaction, grant, execution-policy, target, evidence-remediation, deployment,
  verdict and attack-path lanes.

## Safety

Temporary SQLite and locally generated sessions only. No network I/O, target
interaction, scanning, capability execution, remediation/retest execution,
deployment, verdict generation, or attack-path mutation.
