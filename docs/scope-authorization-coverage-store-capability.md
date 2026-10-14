# Coverage-store capability integrity

LightUp's durable coverage table may only contain capability identifiers that
exist in the canonical capability registry.

## Invariant

`DomainStore.set_coverage()` rejects a coverage write before persistence when
the supplied capability identifier is blank, is not an exact built-in string,
or is not present in the canonical capability registry.

This keeps the durable producer boundary aligned with `CoverageReport`, which
treats unknown capability identifiers as invalid rather than silently
displaying or normalizing them.

A rejected write must leave the engagement's durable coverage unchanged.
Canonical capability identifiers continue to persist normally.

## Scope

This contract narrows reporting/scope integrity only. It does not authorize
capabilities, change activation or execution policy, perform target
interaction, or alter evidence/remediation behavior.
