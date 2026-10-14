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
which arguments select a host, a complete endpoint, one port, or a bounded port
set. Before handler dispatch:

1. resolve the independently authorized top-level asset to a canonical host and,
   when the asset expresses endpoint semantics, its effective port;
2. reject duplicate or malformed argument pairs before projection to a mapping;
3. consume destination roles only from trusted registry metadata and require the
   host/endpoint/port/port-set role sets to be immutable and disjoint;
4. compare host selectors to the exact authorized host without accepting URL or
   inline-port syntax in a host-only field;
5. compare endpoint selectors to the authorized host and, when the asset fixes
   an endpoint, to its effective port;
6. validate scalar port selectors as exact integers in 1..65535 and canonical
   port-set selectors as unique comma-separated decimal ports;
7. when the authorized asset fixes an endpoint, require a scalar port to equal
   that port and a port set to equal the singleton authorized port;
8. only a host-level asset may leave valid port selection to the separately
   authorized tool/capability contract;
9. fail closed on non-string endpoint/host values, bool/string port confusion,
   blank/padded/control-bearing values, userinfo, malformed multiple terminal
   DNS dots, unsupported schemes, noncanonical/duplicate ports, or overlapping
   registry role declarations;
10. do not infer authority from the binding result itself.

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

The destination-role sets must come from trusted tool metadata. Callers must
not declare their own host, endpoint, scalar-port or port-set argument roles.
This matters because current LightUp definitions already split destinations:
`tls_baseline` uses `host` + integer `port`, while
`service_inventory` uses `host` + a bounded `ports` string. Port selection
for host-level assets must still remain inside the already-authorized
capability/tool contract; this reference does not grant arbitrary service access.

## Regression expectations

The isolated reference tests cover:

- host-level asset + same endpoint string with different port/path/query: consistent;
- URL/explicit-port asset + different inline port: reject;
- HTTPS implicit 443 and explicit 443: same endpoint;
- HTTPS-authorized endpoint replayed as HTTP/80: reject;
- split host + scalar port matching an explicit endpoint: consistent;
- split scalar port or port-set widening an explicit endpoint: reject;
- host-level assets may use valid scalar/port-set selectors only subject to the
  separate capability contract;
- bool/string/out-of-range scalar ports and noncanonical/duplicate port sets:
  reject;
- hostname case and one trailing dot: same host identity;
- malformed multi-dot terminal aliases: reject rather than normalize;
- different `url`, `host`, `target`, or `endpoint`: reject;
- duplicate argument names: reject before dict-style overwrite;
- non-string destination values: reject;
- userinfo ambiguity and unsupported schemes: reject;
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
