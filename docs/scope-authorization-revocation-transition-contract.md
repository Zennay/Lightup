# Authorization revocation transition contract (offline)

Status: proposed acceptance contract; **not proof of implementation**. Scope: M7/ST5, central authorization gate. This note does not authorize scans or target contact.

## Invariants

1. An assessment's approval is a snapshot, never a durable permit to invoke later capabilities. Every TARGET_ACTIVE action must re-resolve an exact, current grant and compare it against the original run snapshot.
2. A revoked, expired, missing or replaced grant denies the next action **before** handler invocation or evidence-side effects. A grant with the same identifier but broadened asset, capability, risk level or time window also denies the action. Re-approval creates a new run context; it cannot silently revive the old run.
3. A pre-dispatch authorization check does not solve in-flight revocation. Actions with potentially long duration must have a bounded cancellation checkpoint and must not schedule a follow-on action without another live check. If a handler cannot be interrupted safely, expose that limitation to the operator and block new dispatch.
4. Audit records for denied attempts must be written to a canonical tenant-scoped ledger through a separate bounded denial path. A failed audit sink must never turn denial into permission. Evidence of completed work must not be silently forged or removed on revocation.
5. Revocation or narrowing applies to the exact tenant and authorization lineage only; other tenants must be unaffected. Reuse of a grant identifier by another tenant is not equivalent authorization.
6. Worker retries, queue redelivery and process restarts must perform fresh revalidation and must never treat a cached allow decision as authority.
7. Analysis-only and passive discovery remain non-target-active; this contract must not silently upgrade them to TARGET_ACTIVE.

## Deterministic lab-only acceptance matrix

| Scenario | Expected result |
| --- | --- |
| Grant valid at enqueue, revoked before dispatch | Deny; zero handler calls; no action-success evidence |
| Grant expires while job is queued | Deny at dispatch, regardless of enqueue timestamp |
| Live grant missing or resolver errors | Deny; no fallback to original grant |
| Grant narrowed to exclude requested asset | Deny; no handler calls |
| Same grant ID, broadened capability or risk | Deny; new authorization/run required |
| Same grant ID, live validity starts earlier or expires later | Deny; new authorization/run required |
| Grant revoked during a multi-step run | No next step; cancellation checkpoint before subsequent target action |
| Queue retries after revocation | Every retry denies; no cached approval |
| Tenant A revoked, tenant B still valid | A denied; B independent, provided separate grant and scoped request |
| Denial ledger unavailable | Deny; report audit failure, never permit |
| Analysis-only operation with no target I/O | Remains analysis-only; no implicit TARGET_ACTIVE transition |

## Verification ownership and exit

- Execute tests only with inert in-process handlers and temporary state; no DNS, sockets, real targets, production secrets, exploit payloads or running assessment.
- Avoid collisions: PR #107 owns ToolExecutor source; #954 owns executor grant-integrity composition; PR #982 owns release-gate receipts. This contract adds no code in those areas.
- This document is **not** an implementation claim. Promotion requires source-owner adoption, focused tests on an exact commit, both hosted and permanent VPS checks, review, and recorded release evidence. Never infer permission from green CI alone.
- A real-target action still needs a new explicit operator instruction, exact asset/scope, valid authorization reference and active risk approval.

## Machine-readable outcomes are immutable acceptance targets

The fixture's expected result and guard for each case are fixed by `test_case_results_and_guards_use_closed_vocabulary`. A change from denial to permission, or from fresh validation to a permissive fallback, must not silently pass merely because the scenario identifier remains present. The offline matrix is an acceptance contract only: passing it does **not** prove executor implementation, an authorization grant, target consent, hosted CI, or permanent VPS validation. Any production behavior must be validated separately by the source-owning PR and pinned-head CI before promotion.

## Fixture drift gate

The offline test suite requires exactly five top-level JSON keys and canonical built-in JSON-decoded field types. Unknown metadata is rejected pending review; all scenario result/guard pairs are pinned to the enumerated fail-closed acceptance outcomes. This is **fixture integrity**, not production behavior testing, and cannot be interpreted as an execution authorization. An explicit source-owner integration test must separately exercise revocation between queueing, dispatch, retry, and multi-step execution before release.
