# Typed tool arguments are not target authorization

Status: **DRAFT / HOLD**. This note accompanies the offline real-executor
regressions in PR #1142. It does not authorize any real asset or activation.

## Observed production boundary on main

- `ToolDefinition.validate_arguments()` enforces declared field names,
  presence, and primitive types before the handler is invoked.
- `ToolExecutor.execute()` currently constructs its `ExecutionRequest.asset`
  from `ToolCall.asset`. The dictionary supplied to the handler is separately
  derived from `ToolCall.arguments`.
- A typed STRING parameter can therefore carry a URL/hostname unrelated to
  `ToolCall.asset`. Passing primitive validation is **not** proof that the
  handler's eventual destination is inside the authorized scope.
- No request-provided destination field name, label, header, prompt text or
  network URI may be treated as an authorization source. This is the source
  owner dependency tracked in #1093 and #1092 / #107.

## Source-owner acceptance contract (offline first)

1. Registry/tool implementation owns immutable destination-field metadata
   (and extraction semantics) for each network-capable handler.
2. Before any handler, DNS resolution, socket, queue insertion or action
   evidence write, the trusted pre-I/O gate compares **every effective network
   destination** against the persisted, unexpired, non-revoked, same-tenant
   engagement grant, asset allowlist, capability, and approved risk.
3. No network-capable handler can be registered or dispatched without complete
   destination coverage; unknown/dynamic destinations fail closed rather than
   inheriting `ToolCall.asset` authority.
4. Revocation is checked at the actual pre-I/O boundary against durable state;
   stale context, copied grant, header or model-supplied text cannot resurrect it.
5. An offline integration test registers a synthetic handler with two distinct
   destination values and a deliberately misleading `ToolCall.asset`. The
   invalid destination case must have **zero actual handler, socket, queue and
   action-evidence effects**, while an explicitly approved isolated-lab control
   remains functional.
6. Hosted Python 3.11/3.14 plus canonical permanent VPS safety CI must pass on
   the exact implementation SHA; obtain independent owner review before merge
   or enabling anything beyond lab/plan-only.

## Existing regression coverage

`tests/test_scope_typed_argument_pre_dispatch_20261009.py` exercises the
actual `ToolExecutor` argument-type denial path with instrumented handler and
ledger tripwires plus a synthetic successful lab control. It intentionally
**does not** assert enforcement of destination metadata or durable grants:
those checks require source-owner production integration, not another
standalone mock authorization predicate.

**No real target interaction, network access, scanning, grant issuance, merge
or deployment is included in this branch.**
