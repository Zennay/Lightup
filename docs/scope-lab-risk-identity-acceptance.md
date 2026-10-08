# LAB_ACTIVE requested-risk identity — offline acceptance contract

**Status:** expected-RED acceptance evidence; not an implemented production guard.

The `LAB_ACTIVE` branch in `ExecutionPolicy.decide` currently checks
`is_lab` and returns permit without validating `requested_risk` identity.
Since Python annotations do not enforce runtime types, a caller can supply
`True`, an arbitrary integer, or a foreign `IntEnum` for an alleged risk
value. These must never be interpreted as canonical authorization metadata.

## Acceptance criteria

1. Only an exact `RiskLevel` member is a valid requested-risk identity on
   the lab branch. Reject bool, raw int, foreign IntEnum, string, None, and objects.
2. Valid canonical `RiskLevel.DESTRUCTIVE_LAB_ONLY` remains eligible for
   lab-only policy evaluation when `is_lab is True`.
3. Invalid input is denied **before** it could reach a handler or execution
   path, without mutating the request or generating target traffic.
4. This policy decision by itself does **not** authorize a real lab run.
   The separate activation, mode, approved scope and executor checks remain
   mandatory.

## Ownership and proof

Isolated tests/docs only; the active execution-policy source owner must
implement the fail-closed guard. Do not edit executor, domain, activation,
scope canonicalization, or production source on this branch. The tests are
expected to fail on `main`; do not promote until source-owner integration,
review and pinned hosted + permanent-VPS validation.

No DNS requests, socket activity, scanning, target interactions or real
capability dispatch are performed by this acceptance suite.
