# Durable session integrity acceptance pack

Issue: #710

Pinned parent: `68318a318d828815bc50002114f64037ed06387e` (exact draft PR #670 head).

## Included boundaries

This pack composes three independent tests/docs-only scope-authorization
acceptance slices without changing production source:

1. **#705 — exact session-token identity**
   - a non-exact `str` must not override `encode()` to resolve or revoke a
     different live session;
   - canonical exact token strings remain the green control.

2. **#706 — durable temporal integrity**
   - malformed/naive timestamps, future creation time, inverted intervals and
     persisted lifetimes beyond 30 days fail closed;
   - canonical maximum-lifetime sessions remain the green control.

3. **#708 — durable CSRF-secret integrity**
   - session resolution rejects empty, short, whitespace-padded,
     invalid-alphabet and non-text CSRF values;
   - generated `token_urlsafe(32)` values remain the green control.

## Stop line

This is an acceptance overlay only. It intentionally contains no edits under
`src/lightup/**`. PR #670 retains source ownership of the domain session
boundary. Do not add a second production implementation here.

The corruption/type-confusion cases are expected RED against the pinned parent.
Once the source owner absorbs the guards, restack this pack on that exact head
and use it as the single combined regression proof.

## Non-overlap

The pack does not touch:

- #686 duplicate session-cookie ambiguity or web cookie parsing;
- credential redaction;
- grants or durable execution resolver;
- execution policy or target-capable workers;
- evidence/remediation/retest;
- deployment, verdict or attack-path state.

## Safety

Temporary SQLite and locally generated credentials/sessions only. No network
target interaction, scanning, capability execution, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
