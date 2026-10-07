# Authentication/session authorization integrity pack

Issue: #904

Pinned production source owner: draft PR #670 exact head
`68318a318d828815bc50002114f64037ed06387e`.

## Included contracts

- #803 — session TTL input is an exact built-in integer before durable session
  persistence. Numeric substitutes do not mint authorization lifetime.
- #806 — password input is exact built-in text before credential hashing.
  Polymorphic string encoding cannot substitute different credential bytes.
- #903 — persisted login-lockout timestamps are canonical aware datetimes.
  Malformed or naive durable state fails closed as authentication lockout rather
  than leaking parser/runtime behavior.

## Composition boundary

This pack carries only the six dedicated regression/contract files from
#803/#806/#903 plus this manifest. It changes no production source.

PR #670 remains the sole production owner for the relevant
`src/lightup/domain.py` boundaries.

The existing #705/#706/#708/#710 durable session identity/temporal/CSRF pack is
separate and unchanged.

## Stop line

No target interaction, capability execution, remediation/retest execution,
deployment, verdict or attack-path authority is introduced. This pack only
narrows local credential/session authentication inputs and durable lockout
state.
