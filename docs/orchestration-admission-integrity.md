# Registry and evidence admission integrity — #1520 / #1531 / #1533

**Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a source-code contract repair for existing typed tools and audit handoffs, **not** a grant, a capability enablement or permission to dispatch.

## What changed

**Registry declaration safety (#1520).** A ToolDefinition may no longer hide a parameter constraint by giving two parameters the same name. ToolRegistry validates parameter declaration shape, exact parameter names and kinds, and uniqueness *before* recording a tool. ToolDefinition.validate_arguments applies the same declaration check even for callers that bypass registry admission. The rejection is atomic: no half-registered tool.

**Callable handler admission (#1531).** ToolRegistry.register refuses handlers that are not callable *before* changing the tool registry. It never invokes the handler to perform this check; handler permissions and policy gates remain separate.

**Canonical evidence envelope (#1533).** ToolOutput now requires an actual nonempty built-in string summary, a nonempty/control-free built-in string evidence kind, and exact immutable bytes as evidence payload. It rejects coercion, subclasses or mutable buffers at construction. ToolExecutor checks the exact ToolOutput class and the same content contract once more before forwarding to the existing evidence ledger. Any rejected object cannot be recorded as valid audit evidence by this path.

## Safety boundaries and independent owners

This patch changes only original `src/lightup/ai/orchestration.py` plus this documentation. It does not alter the evidence ledger, metadata validation (independent #1152), existing handler code, capability definitions, grants, ExecutionPolicy, scanners, test files, CI or runners. A callable handler and a well-typed ToolOutput are **not** authorization to call them; existing independent run-risk, mode, tenant, grant, consent and revocation-at-use controls remain required.

There are no active-target calls or tool dispatches in this change. A Python syntax/build inspection is not proof of working integrated security and must not be cited as such. Under the 17 October execution policy no QA/regression/test suites were authored or run. The original pre-existing expected-RED witnesses for these three source issues need separate source-owner review and deliberate promotion upon integration, not deletion/skipping. No merge, deployment, release, handler dispatch or real assessment until security/privacy approval, authenticated separate client/operator permission including action-time revocation, exact-head full hosted and permanently registered named VPS CI and explicit HUMAN GO.

## Additional source repair: handler-controlled evidence metadata (#1152)

The original projection `{"asset": call.asset, **dict(output.metadata)}` previously hid duplicate handler keys and allowed collisions with source-provenance fields. Canonical ToolOutput now requires an exact tuple of exact two-str pairs with unique, nonempty/control-free names; it rejects `asset`, `client_id`, `engagement_id`, `mode`, and `is_lab` as reserved identities. Handler-provided values cannot impersonate this trusted provenance through the pre-existing dict conversion. This extra source patch does not change the separate evidence ledger schema or the original test-owner PR #1152.

## Additional source repair: finite NUMBER admission (#1143)

The original ParamKind.NUMBER accepted NaN and positive/negative infinity; those values defeat ordinary range comparison and JSON interoperability. Direct numeric argument admission now requires an exact built-in int or a finite exact built-in float. Existing finite positive, negative and zero values remain valid. Boolean and polymorphic numeric subclasses do not become accepted through this narrowing. This is *before* registry-dispatched handler execution and evidence handoff, not a per-parameter business-range grant or destination permission. Original #1143 test-owner contracts remain untouched.

## Exact built-in values and immutable call identity (#1095, #1094, #966, #575)

All ParamKind value families now accept only exact built-in values (str/int/bool, or finite float for NUMBER), never subclasses or numeric enum impersonators. ToolCall admission before lookup requires an exact ToolCall and exact nonblank built-in string tool ID and asset; a forged str subclass cannot authorize a different asset via overridable string methods. Argument pairs must be an immutable tuple of exactly two-element tuples, with exact, nonblank, control-free built-in string keys. Duplicate keys fail before dictionary projection instead of silently overriding an earlier field. The policy, handler and evidence ledger have not been invoked by any of these rejections. None of these input checks substitutes for actual persisted authorization/approval or destination binding.

## Canonical registry declaration identity (#907 / #908 / #913)

Tool registry admission now rejects non-builtin/malformed tool and capability IDs, noncanonical interaction/risk enum instances, nonstring descriptions and noncanonical nested parameter declarations. Every parameter name must be a unique nonblank control-free literal string, every required marker an actual boolean, and kind an exact ParamKind, with no coercion. Direct lookups also reject noncanonical outer tool IDs. These validations apply before any registry insert, handler call or evidence write. They preserve the separate full client/tenant/authorization pre-dispatch policy requirement.
