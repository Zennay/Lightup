# ST4 evidence-linked security delta report

The security delta report is the final read-only product projection in Security Twin ST4. It consumes an immutable `FutureAttackPathGraphDiffPreview`, but it does not trust serialized preview state by itself.

Before rendering, LightUp rebuilds the preview from the exact transition proposal, verified transition resolutions, their `RunContext` values and live `StateStore` evidence. Any stale, deleted, cross-tenant, tampered or otherwise drifted lineage therefore fails closed before a report exists.

Each report item preserves the exact ST4 classification and preview action together with the change node, subject node, resolution identity and digest, effect IDs, current attack-path IDs, evidence IDs and capability IDs. The canonical report digest also binds the current/future twin identities and versions, changeset, proposal digest, impact-analysis digest and preview digest.

The export intentionally contains identifiers, hashes, classifications and evidence references only. It does not retain raw customer source code, configuration contents or raw patches.

## Safety boundary

This package remains PLAN/LAB ONLY and read-only:

- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`
- insufficient evidence is explicit and never converted into a clean result
- no real-target interaction, exploit execution, credentials, authorization widening or deployment approval

ST5 policy (for example pass/warn/review/block decisions) is a separate later stage and must consume ST4 output through its own independently proven gate.
