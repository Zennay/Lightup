# Security Twin coverage-integrity acceptance

The current Security Twin consumes durable coverage through
`DomainStore.get_coverage()`. This acceptance layer proves the read-integrity
contract from issue #872 is enforced at the real projection consumer.

## Acceptance

A producer-impossible durable row with either:

- an unknown capability identifier; or
- a non-canonical coverage status

must cause `project_current_twin()` to fail closed before any twin is
returned. The rejected row must remain unchanged in SQLite so validation does
not hide or repair forensic evidence.

A canonical `web-baseline = assessed` row must still project as exactly one
observed `coverage:web-baseline` twin fact.

## Boundary

This is acceptance proof only. It changes no production source and adds no
authorization, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
