# ST5 implementation-plan revision-request integrity pack

This branch composes three independent tests/docs-only acceptance slices directly above the exact #501 head `81cd78f074a777a0380672050082fd21616a447c`.

## Included contracts

- #506 parser input purity: repeated successful and rejected parsing must leave caller-owned persisted input unchanged.
- #510 exact mapping boundary: persisted object parsing accepts only an exact built-in `dict`; polymorphic mapping subclasses fail closed before field reads.
- #535 snapshot isolation: serialization is deterministic, snapshots are detached, forged snapshots fail closed, and post-parse caller mutation cannot change the typed request.

## Composition boundary

The pack adds only the six existing regression/contract files from #506, #510 and #535 plus this manifest. It does not modify #501 production source, its existing tests/docs, the revision-request builder/reviewer producers, revised-plan owners, scope authorization, provider behavior, target-capable code, remediation/retest execution, deployment, verdicts or attack paths.

The component branches all target the same exact #501 parent. This pack does not supersede their source owner; it only provides one collision-free combined validation surface.

## Expected validation state

The parser-purity and snapshot-isolation controls are expected to remain green. The exact-mapping regression remains an expected RED acceptance proof until the #501 source owner absorbs the exact-built-in-dict guard.

Do not promote this pack as fully green while that expected RED remains unresolved.

## Safety

Persistence-integrity tests and documentation only. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
