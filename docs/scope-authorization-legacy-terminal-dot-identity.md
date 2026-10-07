# Legacy Authorization terminal-dot identity

Tracking: #721  
Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

The legacy `lightup.models.Authorization` asset boundary may normalize ordinary host spelling, but it must not turn malformed host text into authority.

- `example.test` and the DNS-root spelling `example.test.` are equivalent.
- Canonicalization may remove **exactly one** terminal DNS root dot.
- `example.test..` is not equivalent to `example.test`.
- A malformed allowlist value ending in two dots does not authorize either the canonical or single-root-dot spelling.
- Existing case folding and outer-whitespace normalization remain valid.

## Expected RED on the pinned source owner

PR #100 currently implements `Authorization.allows_asset()` with `rstrip(".")` for both the caller asset and stored asset entries. Python's `rstrip(".")` removes all terminal dots, not exactly one. The malformed-target and malformed-allowlist regressions therefore fail against the pinned source owner while the canonical controls remain green.

The source repair belongs in PR #100's `src/lightup/models.py` ownership. This acceptance branch deliberately contains no production-source change.

## Collision boundary

This slice does not modify:

- #719 / #117 `ScopeDefinition` trailing-dot source work;
- durable authorization grants or execution-time resolver work;
- access/session identity work;
- activation, execution policy, webapp or target-capable code;
- evidence/remediation, retest, deployment, verdict or attack-path logic.

## Safety

Authorization narrowing only. No external target interaction, scanning, exploit behavior, authority widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
