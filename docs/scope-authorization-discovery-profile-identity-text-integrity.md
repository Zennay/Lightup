# Passive-discovery profile identity text integrity

Issue: #931  
Source owner: draft PR #175  
Pinned source head: `df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`

## Boundary

Immutable prospect identity is only useful when the identity itself is canonical at construction. A malformed, blank or caller-polymorphic identifier must not become the durable owner of later admitted passive-discovery signals.

## Acceptance contract

`ProspectProfile` construction must require both `prospect_id` and `organization_name` to be exact built-in `str` values with non-whitespace content.

The boundary rejects:

- `None` and unrelated objects;
- string subclasses;
- empty strings;
- whitespace-only strings.

Canonical values are preserved exactly. The constructor must not trim, coerce, synthesize or repair identity text.

Production implementation remains owned by PR #175. This child is tests/docs-only and intentionally expected RED until the owner absorbs the boundary.

## Safety

Local in-memory provenance validation only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authorization widening.
