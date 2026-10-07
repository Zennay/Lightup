# ST5 implementation-planning request mapping exactness

Issue: #594

The direct persisted-object parser must accept only an exact built-in `dict`.
Canonical producer `as_dict()` output remains valid. A `dict` subclass with
identical stored content must be rejected before schema traversal, and caller
input must remain unchanged.

Current #230 source uses `isinstance(payload, dict)`, so the subclass rejection
regression is intentionally RED until the source owner absorbs an exact
container check.

This slice owns only the top-level mapping container. It does not modify #230
source and is separate from #592 raw JSON typing, #492 parser purity, scalar
field semantics and live-validation ownership.
