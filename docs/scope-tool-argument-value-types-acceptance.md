# Exact runtime ToolParameter value-type acceptance

## Finding

On exact ToolRegistry-owner PR #156 head
`e84f2cd74d24f143c02b38cc05cb1c4c64352966`, `ParamKind.accepts()`
uses `isinstance`. That is broader than the primitive schema advertised to
tool handlers.

Current effects:
- STRING accepts `str` subclasses;
- INTEGER accepts `int` subclasses and `IntEnum`;
- NUMBER accepts `int`/`float` subclasses and `IntEnum`;
- INTEGER/NUMBER already reject bool explicitly.

A frozen tool definition does not make caller-supplied runtime argument values
canonical. Polymorphic primitive subclasses can carry custom behavior into code
that believes it received a plain JSON-like primitive.

## Required invariant

`ToolDefinition.validate_arguments()` must enforce the primitive boundary:

- STRING: exact built-in `str`;
- INTEGER: exact built-in `int`;
- NUMBER: exact built-in `int` or exact built-in `float`;
- BOOLEAN: exact built-in `bool`.

No subclass, enum, numeric duck type or other polymorphic substitute inherits
authority merely because `isinstance` succeeds.

This contract intentionally does not define per-tool semantic bounds, finite
floating-point requirements, URL/host/port binding or registry metadata
validity. Those are separate gates.

## Acceptance branch

Branch: `chatgpt/scope-tool-argument-value-types-red-20261009`

Pinned parent: exact #156 head
`e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

The regression module contains exact built-in GREEN controls plus expected-RED
cases for:
- string subclass as STRING;
- integer subclass and IntEnum as INTEGER;
- integer subclass, IntEnum and float subclass as NUMBER;
- existing bool rejection for INTEGER/NUMBER as a GREEN denial control.

## Collision boundary

- #913: ParamKind metadata object identity;
- #911: ToolDefinition parameter container/object identity;
- #908: ToolParameter.required metadata type;
- #1094: ToolCall tool_id and argument-key identity;
- #966: duplicate argument-name ambiguity;
- #1093/#1092: destination-role metadata and asset/endpoint binding.

PR #156 retains production ToolRegistry/ToolDefinition source ownership. This
branch adds tests/docs only.

## Safety / promotion

Pure in-memory type validation; no handler, network, target, capability
execution, grant mutation or deployment.

Keep branch-only while the shared permanent VPS lane is occupied. Source-owner
absorption requires exact-head hosted and canonical self-hosted proof before
promotion.
