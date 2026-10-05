# ST4 graph-diff policy decision

This stage consumes one live-validated `FutureAttackPathGraphDiffPreview` and
produces immutable metadata describing whether the preview can proceed to later
operator review or needs more evidence.

It is **not** an attack-path apply step, a security verdict, or a deployment
approval. `attack_path_mutation_allowed=false`,
`future_semantics=unresolved`, and `security_verdict=not_evaluated` remain
hard boundaries.

## Live-validation boundary

`decide_future_attack_path_graph_diff_policy` does not trust a serialized
preview by itself. It rebuilds the preview from the exact transition proposal,
transition resolutions, immutable run contexts, and live evidence ledger. The
presented preview must match that rebuilt value exactly.

This makes stale or tampered preview digests, cross-tenant substitutions,
deleted/stale evidence, proposal drift, resolution drift, and lineage changes
fail closed before a policy decision is emitted.

The policy layer also rejects malformed handoffs before revalidation, including:

- incomplete previews;
- missing identity/digest lineage;
- mutable or duplicate path/effect/evidence/capability lineage;
- duplicate change or resolution identities;
- unsupported graph-diff actions;
- add-path actions that incorrectly name an existing path;
- existing-path actions that omit current-path lineage;
- any attempt to set mutation permission or a security verdict.

## Dispositions

The immutable contract exposes three values:

- `eligible_for_operator_review`: all evidence is complete and the preview
  revalidates exactly;
- `requires_more_evidence`: the preview is valid but explicitly contains an
  `insufficient_evidence` transition;
- `rejected`: reserved for policy rejection semantics. Invalid/tampered input
  currently fails closed before a decision object is created, so callers cannot
  mistake an invalid handoff for a trusted policy record.

This is review-routing metadata only. In particular,
`eligible_for_operator_review` does not mean safe, approved, deployable, or
authorized.

## Deterministic decision binding

The decision SHA-256 binds the exact:

- client, current/future twin identity and versions;
- changeset, proposal, impact-analysis, and preview digests;
- disposition and reason codes;
- ordered change and transition-resolution lineage;
- resolution digests;
- current attack-path, future-effect, evidence, and capability lineage;
- non-mutation and non-verdict boundary.

Exact replay is deterministic.

## Safety boundary

No target interaction, network execution, credentials, exploit execution,
authorization widening, attack-path mutation, or deployment approval is added
by this stage. The sibling ST4 security-delta report is already merged and
consumes the same validated preview independently; ST5 deployment policy remains
separate.
