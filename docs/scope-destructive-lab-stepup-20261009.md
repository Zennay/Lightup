# Destructive lab execution — isolated per-run operator step-up adapter

Status: **DRAFT / HOLD — opt-in producer only, not wired into execution services** (2026-10-09).

## Problem and verified starting point

On current `main`, `RunContext.for_lab()` creates `approved_risk=DESTRUCTIVE_LAB_ONLY` by default. Existing `ToolExecutor.execute` uses that ceiling, plus `is_lab=True` and the product `ExecutionPolicy`, to accept a registered lab tool at risk level 5. A lab label is **not** a per-target operator approval, although LightUp's Notion rules of engagement require explicit opt-in outside normal worker automation for destructive testing. This branch does **not** claim exploitation or remote access: only deterministic offline registry invocation exists in these tests.

## New bounded producer

`src/lightup/destructive_lab_step_up.py` provides opt-in `DestructiveLabStepUpExecutor` wrapping a canonical `ToolExecutor` and a **trusted server-side live approval resolver** (by run ID). It consults the resolver before forwarding an `LAB_ACTIVE` tool marked `DESTRUCTIVE_LAB_ONLY`.

- Default **no resolver → deny** before the tool handler is invoked.
- A matching, exact `DestructiveLabApproval` must bind approval, run, tenant/client, engagement, asset, capability, exact tool ID, operator identity, issuance and expiry; never accept duck-typed copies or an untrusted JSON/prompt-supplied approval.
- The current immutable `RunContext` must be a newly created lab context **after** approval; exact enum risk ceiling is required. Revoked, expired, cross-run, cross-client, cross-engagement, cross-asset, cross-capability and cross-tool approvals are denied.
- Resolution is **live on every call**, so a later revocation affects the next invocation. Resolver exceptions deny without tool handler work or exposing private exception details through explicit exception chaining.
- Each approval lasts **at most 24 hours**, with expiration exclusive; identifiers must be bounded printable ASCII without control characters, whitespace padding or silent coercion. Authorized lab contexts may not carry an unrelated real-target grant.
- Tool definitions must carry exact canonical `InteractionKind` and `RiskLevel` enum values (never raw integer `5`/boolean/strings). Registry identity, handler identity and definition identity are checked again after synchronous resolver callbacks, preventing callback-driven tool swapping.
- Ordinary lower-risk tools continue through existing `ToolExecutor` behavior without requiring a destructive approval.
- No attempts are made to treat `is_lab` as proof of an actually isolated network. Actual lab isolation, persistent approval authenticity and runtime admission are still external requirements.

## Confirmed raw-executor RED canary

`tests/test_scope_destructive_lab_stepup_20261009.py` includes
`test_red_default_raw_executor_has_no_destructive_stepup_gate_yet` as an
explicit `unittest.expectedFailure`: the existing raw executor **does**
run the synthetic destructive-marked lab handler without this wrapper.
A green suite with one expected failure is **not** evidence the production
gap has been fixed. The production owner must first wire a verified gate and
replace the xfail with a normal passing denial assertion on the real entrypoint.
Tracking: [#1173](https://github.com/Zennay/Lightup/issues/1173);
owner handoff: [PR #107](https://github.com/Zennay/Lightup/pull/107).

## Runtime acceptance and *non*-claims

An application/executor owner must integrate the wrapper at **every** destructive-capable dispatch route, supply a canonical operator-approved durable record resolver that cannot be influenced by AI prompts, and require actual isolated lab environment attestation. Do not deploy from this draft. The default `ToolExecutor` is unchanged and **still does not enforce the new check**; instantiating it directly bypasses this *optional* adapter. **Important concurrency limitation:** repeat identity checks close synchronous callback substitution, **not** races with another thread mutating registry/approvals between validation and dispatch. The source owner must freeze the registry and implement a transactional approval-consumption/dispatch boundary or appropriately lock the authority state. Approval records in the tests are synthetic and never authorize a live target.

Suggested source-owner release gates:

1. Independent approval identity/role proof, operator review and a durable revocation transaction. Do not accept approvals encoded in `ToolCall.arguments`, HTTP fields or model output.
2. Verify actual lab confinement and deny all external destinations at transport/network level, even after policy approval.
3. Wire the wrapper into actual lab dispatch; forbid alternate raw executor dispatch paths at construction/import/review.
4. Replace isolated acceptance with integrated real-entrypoint tests proving no handler starts without approval and denial causes zero state/evidence change.
5. Run hosted Python 3.11/3.14 preflight and canonical permanent VPS safety CI on **the exact final SHA**; obtain independent reviewer signoff.
6. Preserve the overall **plan-only / lab-only, no active real-target** posture until explicit human permission. No scan, external network call, production deployment, active grant or proxy reload here.

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_scope_destructive_lab_stepup_20261009.py' -v
```

Only temporary local SQLite and no-op synthetic evidence are used by the tests. A passing result proves **this opt-in adapter** in offline tests, *not* deployment integration, approval provenance, operator authority, or network isolation.

## Parallel ownership

This isolated branch adds only `src/lightup/destructive_lab_step_up.py`, a new test file, and this document. It does not edit the ToolExecutor source owned by PR #107 or `ExecutionPolicy`, `RunContext`, web app, WebSecurity, consent/store, worker engine, Nginx, or any currently held authorization PR paths.
