# Scope-authorization integration gates (M7 / ST5)

This checklist is a **non-executing release contract** for integrating parallel fail-closed hardening work. It does not grant permission to scan, access, or test any external system.

## Ownership and integration order

- The production ToolExecutor / live resolver boundary is owned by draft PR #107. Do not cherry-pick fixes into its source while that owner remains active.
- The production passive discovery boundary is owned by draft PR #175. Discovery contract packs are tests/docs only until its owner integrates them.
- The canonical StateStore and authorization policy implementations retain their respective active owners. Check the current PR list immediately before promotion; this ownership map may become stale.
- The independently prepared #948, #949, #951, #953 contracts compose into issue #954. Avoid merging redundant test branches on top of an already composed pack.
- Require exact commit identities rather than relying on mutable branch names for validation receipts.

## Gate A — authorization prerequisites

A TARGET_ACTIVE operation must fail closed if **any** of these conditions holds:

1. No explicit, currently valid approval applies to the intended client, engagement, asset, capability and risk tier.
2. The run snapshot has expired or is not yet valid, even if live authorization has a wider time window.
3. Live authorization has been revoked, is missing, or has a different grant identity.
4. Live authorization expands assets, capabilities, risk or validity relative to the immutable run snapshot. Exclusions must not be relaxed.
5. The caller replaces the canonical registry, policy, authorization resolver or evidence ledger retained at construction.
6. A substituted duck-typed or subclassed boundary object evades expected exact-object identity checks.
7. Authorization cannot be persisted with an unambiguous audit/evidence lineage.

**Expected outcome:** reject before any handler invocation or evidence success write, without mutating snapshots, grants, or durable authorizations. Negative proofs must use inert test handlers and temporary/offline stores.

## Gate B — passive discovery separation

A public prospect discovered from passive signals is **never** an execution grant. Admission must validate signal category, public provenance and exact profile/signal identity even for collection mutation, reconstruction, and replacement paths. The profile's existence cannot transition a target into TARGET_ACTIVE mode; require an independently approved and scoped authorization object.

## Gate C — regression and runner proof

For each integration candidate, collect:
- source PR and exact head SHA;
- the **list of changed production paths** and conflict ownership clearance;
- deterministic fail-closed negative tests paired with canonical allowed-path tests;
- evidence that no handler runs or successful evidence is emitted on rejected calls;
- hosted test result and independent permanent VPS proof on the exact same head, with runtime/test counts and runner identity;
- a recorded review of the final aggregate diff, not just standalone component branches.

Queued or cancelled jobs are **not** green proof. Do not restart a competing runner or cancel active work merely to obtain a receipt. If the pinned head changes, previous proof no longer satisfies the current-head gate.

## Gate D — safe promotion and stop conditions

Promote only after the owner integrates the tests and implementation, the exact-head checks pass, and there is an explicit review of authorization narrowing. If any invariant fails or source ownership conflicts, keep the patch draft and publish a focused failing regression or a review finding instead of broadening access to make CI pass.

**Not covered by this contract:** live-target activation, exploit execution, external probing, deployment, operator approval, or any permission to bypass the existing consent workflow.

References: #107, #175, #948, #949, #951, #953, #954; LightUp Notion Current State & Handoff, 2026-10-07.
