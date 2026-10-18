# Registry and evidence admission integrity — #1520 / #1531 / #1533

**Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a source-code contract repair for existing typed tools and audit handoffs, **not** a grant, a capability enablement or permission to dispatch.

## What changed

**Registry declaration safety (#1520).** A ToolDefinition may no longer hide a parameter constraint by giving two parameters the same name. ToolRegistry validates parameter declaration shape, exact parameter names and kinds, and uniqueness *before* recording a tool. ToolDefinition.validate_arguments applies the same declaration check even for callers that bypass registry admission. The rejection is atomic: no half-registered tool.

**Callable handler admission (#1531).** ToolRegistry.register refuses handlers that are not callable *before* changing the tool registry. It never invokes the handler to perform this check; handler permissions and policy gates remain separate.

**Canonical evidence envelope (#1533).** ToolOutput now requires an actual nonempty built-in string summary, a nonempty/control-free built-in string evidence kind, and exact immutable bytes as evidence payload. It rejects coercion, subclasses or mutable buffers at construction. ToolExecutor checks the exact ToolOutput class and the same content contract once more before forwarding to the existing evidence ledger. Any rejected object cannot be recorded as valid audit evidence by this path.

## Safety boundaries and independent owners

This patch changes only original `src/lightup/ai/orchestration.py` plus this documentation. It does not alter the evidence ledger, metadata validation (independent #1152), existing handler code, capability definitions, grants, ExecutionPolicy, scanners, test files, CI or runners. A callable handler and a well-typed ToolOutput are **not** authorization to call them; existing independent run-risk, mode, tenant, grant, consent and revocation-at-use controls remain required.

There are no active-target calls or tool dispatches in this change. A Python syntax/build inspection is not proof of working integrated security and must not be cited as such. Under the 17 October execution policy no QA/regression/test suites were authored or run. The original pre-existing expected-RED witnesses for these three source issues need separate source-owner review and deliberate promotion upon integration, not deletion/skipping. No merge, deployment, release, handler dispatch or real assessment until security/privacy approval, authenticated separate client/operator permission including action-time revocation, exact-head full hosted and permanently registered named VPS CI and explicit HUMAN GO.
