# Strict ExecutionRequest admission (opt-in, draft / HOLD)

## Why

The current baseline `ExecutionPolicy.decide` compares `RiskLevel` (an
`IntEnum`) numerically and routes non-matching `InteractionKind` values to
the target-active branch. Python's coercion/equality behavior means that a
noncanonical request envelope can be handled as if it carried typed authority.
Typed `ToolDefinition` and `RunContext` are immutable *dataclasses*, but
dataclass annotations do not validate runtime input values.

## Isolated implementation

`src/lightup/strict_request_policy.py` provides
`StrictExecutionRequestPolicy(ExecutionPolicy)`. It checks **exact built-in
runtime types** for the request, interaction enum, risk enum and lab boolean;
rejects whitespace/control-bearing/polymorphic asset and capability identities;
rejects non-exact grant objects; and refuses lab-marked target-active requests
even when invoked without the normal executor. Only after these checks does it
delegate to the existing product authorization/scope/risk policy.

Opt-in integration for a **synthetic/offline local harness**:

```python
from lightup.strict_request_policy import StrictExecutionRequestPolicy

executor = ToolExecutor(registry, state, policy=StrictExecutionRequestPolicy())
```

This is **not installed** into the shared live executor, web app, proxy, or
deployment paths. It performs **no** tool I/O, DNS resolution, scanning, grant
creation or external networking.

## Verified by new tests

The additive `tests/test_scope_strict_execution_request_20261009.py`
exercises direct gate denials and **real** `ToolExecutor` dispatch with a
temporary SQLite evidence store and a pure synthetic handler:

- Non-enum interaction lookalikes and non-enum risk lookalikes are rejected.
- `is_lab` must be exactly `bool`; a lab marker cannot promote a
  `TARGET_ACTIVE` request into authorized real-target execution.
- Polymorphic/blank/control-bearing asset and capability identities, grant
  subclasses and request subclasses are rejected.
- Valid scoped/authorized low-impact synthetic work still emits one ledger
  item, while invalid typed requests execute **zero** handlers and emit **zero**
  evidence rows.
- Out-of-scope assets, expired grants and risk escalation are still denied by
  the inherited product policy.

## Limitations and promotion gates

This wrapper validates only its request envelope. It **does not** prove
immutable registry binding, authentic operator signatures, durable grant
revocation, dispatch-time grant freshness, client/engagement binding, real lab
confinement, safe parameter-to-target binding or absence of concurrency races.
An exact-type `AuthorizationGrant` can still be constructed by untrusted code;
**type validation is not cryptographic or database-backed authorization.**

The shared ToolExecutor / live grant source owner (#107) owns any production
integration. The optional destructive lab step-up (#1172) is a separate gate
and remains draft. Production MUST be held until these owner lanes compose
their controls, independent security review, green exact-HEAD hosted and
permanent `vps-bb300bba` CI, and explicit authorization for any real target.

This slice deliberately changes **three new paths only**, avoiding source
ownership in #107, #156, #163, #182, #202, #1162 and parallel WSGI/ingress
guards. Do not merge or deploy this draft solely on green unit tests.
