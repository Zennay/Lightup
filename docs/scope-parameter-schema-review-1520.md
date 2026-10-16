# Scope #1520 — ToolDefinition parameter-name admission (offline only)

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Issue [#1520](https://github.com/Zennay/Lightup/issues/1520). This branch does not authorize, dispatch, scan, deploy, grant or merge.

## Original installed-source observation

`ToolDefinition.validate_arguments()` builds a `known` dictionary keyed by `ToolParameter.name`, silently collapsing duplicate names. It then walks the original tuple for requiredness/type checks. `ToolRegistry.register()` currently admits these contradictory definitions. Thus two parameters named `asset` with STRING and INTEGER types can enter the registry, even though no caller value satisfies both. Identical repeated types are also accepted as an ambiguous schema.

**This is a schema ambiguity / availability problem, not an observed authorization bypass.** No real asset was tested.

## Delivered, owner isolated

- A pure **unwired** `src/lightup/scope_parameter_schema_review_1520.py` returns only `HOLD` or `REVIEW_ONLY`. Every output has `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`.
- Exact `ToolDefinition` with exact tuple of 0–32 exact `ToolParameter` objects is required. Each parameter has a unique exact builtin ASCII lowercase identifier, maximum 64 characters, exact `ParamKind`, bool `required`, string description. No coercion, normalization or polymorphic user-provided values.
- Isolated `tests/test_scope_parameter_schema_review_1520.py`: ordinary positive, boundary, duplicate/Unicode/type, input-purity and no-network regression checks; one canonical installed `ToolRegistry.register` control; **two intentionally OPEN installed-source `expectedFailure` assertions** proving duplicates are not yet rejected at actual registration.
- A separate opt-in hosted Python 3.11/3.14 workflow checks only the owned test file. It is **not** the original complete CI or permanent VPS proof.

## Handoff to source owner

The real fix belongs in existing `ToolRegistry.register` source-owner PR [#156](https://github.com/Zennay/Lightup/pull/156) (with #907/#911/#908/#913 as separate sibling contracts), **before registry insertion**, without changing permissions or granting scope. When the real source fix is integrated, turn the two expected failures into ordinary assertions and verify their result and canonical controls with full original hosted and registered permanent VPS matrix at identical commit SHA. Do not count expected failures as a production fix.

Other owners retain their existing files, branches and runner/workflow. No existing product source, existing workflow, active handler, grant, activation policy, account, network or release was modified here.

Remaining external gates: authentic separate client and operator consent, revocation at use, source-owner repairs, independent security/privacy review, entire exact-head original hosted and genuinely registered `vps-bb300bba` Python 3.11/3.14 GREEN, and explicit human GO. **Keep PR draft; do not merge or deploy.**


## W2: opt-in canonical JSON intake (still zero authority)

New `scripts/scope_parameter_schema_cli_1520.py` reads only a maximum of 8192 bytes from stdin. Input must be exactly compact RFC-style ASCII JSON in the shape:

```json
{"parameters":[{"name":"asset","kind":"string","required":true}]}
```

The CLI rejects duplicate JSON keys before mapping, unknown/missing fields, re-encoded or noncanonical JSON, Unicode escape aliases, nonstandard floats, malformed values, 33+ parameters and oversized bytes. It uses the same reviewer as the in-memory checks. All output is a single fixed JSON line with **four false authority fields**, no input echo. Exit `2` is fictional schema `REVIEW_ONLY`; exit `3` is generic `HOLD`; **exit 0 is never possible**. It is never called from ToolRegistry or ToolExecutor.

True child-process `tests/test_scope_parameter_schema_cli_1520.py` verify valid/invalid/byte-boundary/fragmented stdin, no echo and false authority. The uniquely owned hosted workflow executes both isolated source and CLI suites on Python 3.11 and 3.14 without secrets or access to real assets. Even a green workflow does not verify original production admission or grant safety.
