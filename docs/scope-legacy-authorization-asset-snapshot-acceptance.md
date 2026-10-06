# Scope authorization: legacy Authorization asset snapshot acceptance

Issue: #300

This tests/docs-only contract is stacked on exact PR #100 head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

Legacy authorization asset scope must be immutable after construction. A
caller-owned mutable list may not remain aliased behind a frozen
`Authorization` object.

The contract proves:

- mutable input is snapshotted into an immutable tuple;
- later caller mutation cannot widen an existing grant;
- later caller mutation cannot narrow an existing grant;
- canonical tuple-backed exact asset authorization remains unchanged.

Expected RED on #100: `frozen=True` prevents attribute reassignment but does
not convert a runtime list passed to `assets`; `allows_asset()` reads the
same caller-owned list on every decision.

No source files are modified. `models.py`, `scope.py`, activation and the
PR #100/#104 source stack remain owned by their existing workers.

Safety: authorization-scope narrowing only; no DNS/network I/O, target
interaction, scanning, execution, remediation/retest execution, deployment,
verdict creation, or attack-path mutation.
