# Scope-authorization offline release gate ledger

Status: **documentation-only acceptance contract**. This does not authorize testing or enable real-target execution.

## Mandatory preflight evidence

Every future promotion from M7/ST5 must record the immutable commit SHA under test, review approval, and the following independent checks. A queued workflow is **not** a pass; only a successful result from the pinned SHA counts.

| Gate | Failure must occur before | Acceptance evidence |
| --- | --- | --- |
| Explicit owner approval, scoped tenant and engagement | tool handler and network I/O | signed/recorded approval reference tied to the exact engagement |
| Canonical immutable run authorization snapshot | handler dispatch | rejected malformed/substituted grant and unchanged stored context |
| Exact current grant revalidation | handler dispatch | revoked/missing/mismatched grant denies even if snapshot remains valid |
| Live authority is never wider than the run snapshot | handler dispatch | asset, exclusions, capability, risk and validity-window monotonicity regressions |
| Assessment mode cannot silently become active | handler dispatch | analysis-only and passive modes reject active tools despite valid grants |
| Risk escalation requires new explicit approval and new run | handler dispatch | raised-risk regression leaves the existing run unchanged |
| Original policy, tool registry, resolver and evidence ledger remain bound | handler dispatch | rebinding/duck-type/subclass regressions deny without calling the handler |
| Successful authorized execution records canonical evidence | success acknowledgement | durable evidence identity and tenant/run linkage; failed calls produce no success evidence |
| Safe fixture isolation | any external connection | test fixture is offline or explicitly owned loopback lab; no arbitrary external targets |

## Operator promotion checklist

1. Confirm the exact SHA and enumerate open PR ownership. Do not cherry-pick another worker's production edits.
2. Keep **real-target activation disabled**. Do not treat lab success, documentation or model judgments as consent.
3. Obtain offline regression results for both allow and deny paths; ensure denied calls dispatch zero handlers and create zero success evidence records.
4. Verify the same SHA against hosted CI and the designated permanent VPS lane; record run IDs and exact test counts.
5. Reconcile any changed approval, tenant, scope, time, capability or risk data against the immutable run snapshot. Widening requires a newly approved run, never mutation in place.
6. Publish the reviewer, SHA, CI and permanent-run receipts. Keep this gate pending on missing, cancelled or superseded proof.

## Ownership and exclusions

This ledger covers **release acceptance documentation only**. It does not modify `src/lightup/ai/orchestration.py`, `execution_policy.py`, `engagements.py`, `state.py`, target adapters, discovery, or production activation. Existing PR #107 owns the ToolExecutor implementation; #954 collects its evidence/resolver/monotonicity regression contracts. Any missing control belongs with the existing owner rather than being silently duplicated here.

No scan, DNS lookup, external target contact, security verdict, deployment or permission escalation is performed by this document.
