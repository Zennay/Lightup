# Coverage-store status integrity

Coverage status is durable authorization/reporting state. Validation and
persistence must therefore observe one canonical value.

## Invariant

`DomainStore.set_coverage()` accepts only an exact built-in string status,
resolves it through `CoverageStatus`, and persists the enum's canonical
`.value`.

A raw unknown status or a string subclass fails before mutation. Rejected
writes leave durable coverage unchanged. Canonical values such as
`partially_assessed` continue to round-trip unchanged.

## Dependency and scope

This is a child contract of issue #867 / PR #869. The parent owns capability-ID
validation. This child only narrows status identity and persistence.

It does not modify `coverage.py`, labsync, evidence-remediation, activation,
execution policy, target workers, or any network-capable path.
