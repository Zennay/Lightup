# ST5 freshness-constraints consumer persisted runtime types

Issue #748 isolates the outer persisted runtime-type boundary introduced by
freshness-constraints consumer PR #131.

## Boundary

The consumer accepts either serialized JSON text or an already-decoded persisted
object before delegating to the strict #68 constraints parser and live validator.
Canonical persistence supplies exact built-in values:

- `constraints.to_json()` produces an exact built-in `str`;
- `json.loads(constraints.to_json())` produces an exact built-in `dict`.

Python subclasses of those values cannot originate from JSON persistence. Broad
`isinstance` checks at the outer consumer boundary therefore admit an input
shape wider than the persisted contract.

## Acceptance

The dedicated regression requires:

- exact built-in JSON text remains accepted;
- exact built-in decoded object remains accepted;
- equal-content `str` subclasses fail closed before JSON decoding;
- equal-content top-level `dict` subclasses fail closed before strict parsing;
- rejected caller-owned values remain unchanged.

The subclass cases are intentionally expected RED on the pinned #131 source head
because its `_persisted_payload()` currently uses broad `isinstance` checks.

## Non-overlap and stop line

This branch changes tests/documentation only. PR #131 retains its consumer source.
#612 remains the underlying #68 direct-parser persisted-object exactness contract,
#317 owns snapshot isolation, and #323/#329 own cross-parser input purity.

No evidence collection, capability/tool choice, target interaction,
remediation/retest execution, deployment, classification, security verdict, or
attack-path mutation is introduced.
