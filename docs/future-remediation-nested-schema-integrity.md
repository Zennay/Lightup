# ST5 nested remediation schema integrity

This tests/docs-only gate is stacked on exact #263 head
`76e934848a431208610eed5248b362aedab7c55c`. It complements #265: #265 owns
recursive duplicate-key rejection, while this gate owns exact nested object
shape after unambiguous JSON decoding.

## Invariant

Persisted remediation objects must reject schema widening and schema erosion
inside nested structures, not only at the top level.

The regression covers:

- all eight original/revised top-level remediation artifacts for required-field
  schema erosion;
- remediation authoring items;
- authoring evidence references;
- original remediation review checks;
- revised remediation review checks.

For each nested object kind, both an unexpected field and a missing required
field fail closed at the strict parser boundary. Replacing a nested object with
a list or scalar also fails closed before digest validation. The direct
persisted-dict entry points reject both nested schema widening and erosion, so
callers cannot bypass the JSON path by pre-decoding input. Canonical baseline artifacts
continue to round-trip unchanged.

## Collision boundary

This slice adds only a dedicated regression module and this document. It does
not modify production source, #255/#256/#258/#261/#263-owned files, the active
#265 nested duplicate-key files, or any scope-authorization surface.

## Safety boundary

This is persistence/schema integrity only. It creates no model call, target
interaction, tool execution, remediation or retest execution, deployment,
security verdict, or attack-path mutation.

## Promotion gate

Promotion remains linear above #263 and requires exact-head hosted proof plus
canonical self-hosted LightUp proof. Do not treat structural parsing as live
authorization; existing complete live-lineage validators remain mandatory.
