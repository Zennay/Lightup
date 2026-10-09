# ToolCall field identity acceptance

## Scope

This is a field-level child of the TARGET_ACTIVE executor boundary on exact PR
#107 head `c37ee27d922a7dd400eee1db39268f4a6269e431`.

It does not own the outer `ToolCall` object boundary (#946), runtime asset
identity (#575), duplicate argument names (#966), ToolRegistry production schema
(#156), or ToolExecutor source (#107).

## Finding

`ToolCall` is frozen and annotated, but Python annotations do not make its
fields exact runtime types.

The current executor:

1. reads `call.tool_id` and passes it to `ToolRegistry.get()`;
2. calls `call.arguments_dict()`, which projects tuple pairs through `dict()`;
3. validates projected argument names with ordinary mapping membership/lookups.

An exact outer `ToolCall` can therefore still contain a `str` subclass as
`tool_id` or as an argument-name key. A subclass carrying the same text as a
registered canonical identifier crosses the trusted identity boundary today.

## Required invariant

Before registry lookup or argument projection can influence authorization or
execution:

- `type(call.tool_id) is str`;
- `tool_id` is non-empty, bounded and canonical according to the registry's
  identifier contract;
- every raw argument pair has an exact built-in `str` key before conversion to
  a mapping;
- each key is non-empty/bounded/canonical according to the parameter-name
  contract;
- string subclasses fail closed even when their underlying text exactly equals
  a valid tool or parameter name;
- rejection happens before handler invocation and before evidence persistence.

The exact error type can remain `OrchestrationError`; malformed call shape is
not an authorization success/failure result.

## Acceptance branch

Branch: `chatgpt/scope-toolcall-field-identity-red-20261009`

Pinned parent: exact #107 head
`c37ee27d922a7dd400eee1db39268f4a6269e431`.

The regression module provides:
- one GREEN control using exact built-in string fields;
- one expected-RED `tool_id` string-subclass case;
- one expected-RED argument-key string-subclass case;
- zero-handler and zero-evidence assertions for both rejection paths.

No production source is modified.

## Safety / runner posture

The handler is inert and writes only temporary local evidence if the current
boundary incorrectly reaches it. There is no DNS/network I/O, target
interaction, scanning, remediation/retest, deployment, verdict or attack-path
mutation.

Keep this acceptance branch-only while #1092 occupies the canonical permanent
VPS lane. The eventual source-owner repair must receive exact-head hosted and
canonical self-hosted proof before promotion.
