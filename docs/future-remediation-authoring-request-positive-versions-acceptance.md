# ST5 remediation authoring request — positive twin-version acceptance

Issue #415 isolates one persisted-boundary invariant on the exact active #198
head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Contract

The live remediation-authoring producer lineage only carries versioned current and
future twin snapshots. Therefore persisted `current_twin_version` and
`twin_version` must both remain exact positive integers.

This acceptance slice proves:

- a canonical WORSENED producer request still round-trips through the strict
  persisted parser;
- replacing either twin version with `0` is rejected;
- the forged request recomputes `request_sha256`, so stale-digest rejection
  cannot satisfy the contract;
- existing bool-vs-int, schema, digest and live-lineage gates remain owned by
  #198 and are not modified here.

## Expected pre-fix result

The two zero-version subcases are intentionally RED on the current #198 parser,
which uses a generic non-negative integer check. The #198 source owner can
absorb the narrow positive-version requirement and then re-run this exact
acceptance contract. Promotion requires both subcases to become green without
weakening the canonical producer control.

## Collision and safety boundary

This branch adds tests and documentation only. It does not modify #198/#196/#60
source or tests and is distinct from #409/#410 capability/path identity and
ordering, #411/#412 canonical evidence kind, and #413/#414 exact capability
coverage.

No model invocation, target interaction, code/config generation, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
