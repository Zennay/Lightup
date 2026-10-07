# Scope authorization — assessment-request mode identity

Issue #876 pins the runtime type boundary for the assessment mode accepted by
`DomainStore.submit_assessment_request()`.

## Contract

Assessment-request intake must accept only a canonical `AssessmentMode`
member for `requested_mode`.

A foreign enum or duck object that merely exposes a matching `.value` is not
canonical authorization provenance and must fail before persistence. The
producer boundary must never normalize such an object into a trusted durable
`AssessmentMode`.

A canonical `AssessmentMode.AUTHORIZED_ASSESSMENT` request remains valid and
must round-trip through the durable reader as the same enum member.

## Why this matters

Assessment requests are intended to become provenance for later request-to-grant
binding (#177). That downstream boundary should be able to trust that the
persisted request mode originated from LightUp's own vocabulary rather than a
foreign object whose only compatible surface was a matching string value.

## Expected state on the pinned parent

Pinned parent: `main` at
`1abc16a66fc490b1ba7272890dfbf498482fca9c`.

The canonical control is expected GREEN. The foreign enum and duck-object cases
are expected RED because the current producer persists
`requested_mode.value` without first proving that the caller supplied an
actual `AssessmentMode`.

## Safety and collision boundary

Tests and documentation only. No production source is modified. The slice does
not take over the active coverage-store, assessment-risk, approval-decision,
request-to-grant, execution, evidence-remediation, deployment, verdict or
attack-path owners. It performs no DNS/network I/O or target interaction.
