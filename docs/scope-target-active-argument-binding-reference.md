# TARGET_ACTIVE argument-to-asset binding reference

## Why this exists

LightUp authorizes a top-level asset before target-active execution. A tool call
must not be able to keep that approved asset in its envelope while placing a
different destination inside a network-bearing argument such as `url`,
`host`, `target`, or `endpoint`.

That would create an authorization confused-deputy gap: policy could approve one
asset while the handler receives another destination.

## Acceptance contract

For every TARGET_ACTIVE tool definition, the trusted registry must identify
which arguments can select or override a network destination. Before handler
dispatch:

1. resolve the independently authorized top-level asset to a canonical host;
2. reject duplicate or malformed argument pairs before projection to a mapping;
3. for every registry-declared network-bearing argument, resolve a canonical
   host without DNS or network I/O;
4. require every such host to equal the authorized asset host exactly after the
   agreed canonicalization;
5. fail closed on non-string, blank, padded, control-character, userinfo,
   malformed, unsupported-scheme, or otherwise ambiguous destination values;
6. do not infer authority from the binding result itself.

A positive binding result means only: declared destination arguments are
consistent with the already-authorized asset. It does not prove grant issuance,
tenant ownership, engagement state, approval, revocation freshness, risk,
capability authorization, or dispatch eligibility.

## Required production integration

This reference does not modify the production executor. PR #107 remains the
source owner for live authorization and dispatch enforcement.

The production owner should integrate this invariant after strict ToolCall
argument-shape validation and live grant revalidation, but before any handler,
retry, queue handoff, DNS lookup, socket operation, or evidence-producing target
interaction.

The destination-key set must come from trusted tool metadata. Callers must not
be allowed to declare their own network-bearing argument names.

## Regression expectations

The isolated reference tests cover:

- same-host URL with different port/path/query: consistent;
- hostname case and one trailing dot: same identity;
- different `url`, `host`, `target`, or `endpoint`: reject;
- duplicate argument names: reject before dict-style overwrite;
- non-string destination values: reject;
- userinfo ambiguity: reject;
- blank/whitespace-padded values: reject;
- unrelated metadata values: do not reinterpret as destinations;
- caller input immutability;
- strict registry destination-key container typing.

## Collision boundary

This slice is intentionally separate from:

- PR #107 production live-grant executor ownership;
- PR #180 LAB_ACTIVE planner argument-to-scenario-target binding;
- PR #966 duplicate ToolCall argument RED contract.

It adds only a standalone offline reference test and this contract document. It
does not grant permissions, change production policy, contact targets, perform
DNS/network I/O, scan, dispatch a capability, deploy, or claim production
enforcement.

## Promotion gate

Do not treat this reference as a security control until the production owner has
implemented the invariant in the real TARGET_ACTIVE path and exact-head hosted
plus canonical permanent VPS tests prove zero handler and zero target/network
I/O for every denial case.
