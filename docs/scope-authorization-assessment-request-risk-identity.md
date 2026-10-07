# Scope authorization — assessment-request risk identity

Issue #875 pins the type boundary for `DomainStore.submit_assessment_request()`.

## Contract

Assessment-request intake must accept only a canonical `RiskLevel` member for
`requested_risk`.

The following values are non-canonical even when Python can convert them to the
same integer stored in SQLite:

- `bool`;
- raw `int`;
- a foreign `IntEnum`.

They must fail before any assessment-request row is created. The boundary must
not normalize producer-impossible input into a trusted durable `RiskLevel`.

A canonical `RiskLevel.STANDARD` request remains valid and must round-trip
through the durable reader as the same enum member.

## Why this matters

Assessment requests are authorization provenance. Future request-to-grant
binding (#177) should be able to trust that the stored requested risk originated
from LightUp's own risk vocabulary rather than an integer-like value that was
silently coerced during persistence.

This acceptance slice deliberately does not change approval decisions, grant
issuance, execution policy, activation or any target-capable behavior.

## Expected state on the pinned parent

Pinned parent: `main` at
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

The canonical control is expected GREEN. The three non-canonical cases are
expected RED because the current producer persists `int(requested_risk)`
without first proving that the caller supplied a real `RiskLevel`.

## Safety and collision boundary

Tests and documentation only. No production source is modified. The slice does
not take over the active coverage-store, durable grant, approval-decision,
request-to-grant, execution, evidence-remediation, deployment, verdict or
attack-path owners. It performs no DNS/network I/O or target interaction.
