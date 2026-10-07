# ST5 revised-plan direct digest coherence

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan producer #503 at exact parent `6cc2d06096c60fc38fd63350206029c9703efdd6`.

It owns only direct typed-artifact digest coherence. #557/#558 retain lifecycle/action-authority ownership, #524 retains producer provenance bounds, and #511 plus its children retain persisted parser/type/snapshot ownership.

## Invariant

A `FutureRemediationImplementationPlanRevisionProposal` must not exist in memory with canonical-looking content or lineage that no longer matches its recorded `revised_plan_sha256`.

Direct construction or `dataclasses.replace()` must reject:
- a changed canonical `revision_request_sha256` with the old revised-plan digest;
- changed bounded planning text with the old revised-plan digest.

The constructor must reject rather than repair or silently recompute caller-supplied state.

## Expected RED

At #503 head the frozen dataclass has no constructor validation. Both stale-digest replacements succeed, so the dedicated rejection tests intentionally fail until the source owner adds typed digest validation.

## Safety

Only deterministic in-memory planning fixtures are used. No external model/network call, target interaction, scanning, tool/remediation/retest execution, deployment, security verdict, or attack-path mutation occurs.
