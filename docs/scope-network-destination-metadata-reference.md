# Trusted network-destination tool metadata reference

## Purpose

TARGET_ACTIVE argument binding needs a trusted answer to one question before
dispatch: **which tool parameters are allowed to select or override a network
destination?**

The current executor-owner head (#107) has typed tool parameters, but no
registry-owned destination classification. A planner, model, request payload, or
caller must never be allowed to supply that classification because doing so
would move part of the authorization boundary into attacker-controlled data.

This contract supports issue #1093 and is the metadata prerequisite for the
argument-to-authorized-asset binding captured by PR #1092.

## Reference contract

A production design should provide an immutable, typed destination role on the
trusted tool definition/parameter metadata. The roles must distinguish at least
a host selector, a complete endpoint selector, a scalar port selector and a
bounded port-set selector. Before a tool definition can enter the registry:

1. the parameter collection is an exact immutable container;
2. every parameter is an exact trusted metadata type;
3. parameter names are canonical, bounded, non-empty and unique;
4. parameter kind and destination role use exact known enum values;
5. host and complete-endpoint roles require string parameters;
6. scalar-port roles require integer parameters and port-set roles use the
   registry's canonical bounded string representation;
7. ordinary string fields such as notes or paths do not become destinations by
   name guessing or caller declaration;
8. malformed, polymorphic, duplicate or unknown metadata fails registration
   closed rather than being normalized;
9. extraction returns immutable, disjoint role-specific name sets owned by the
   trusted definition.

A successful metadata validation is **not authorization**. Live grant,
tenant/engagement ownership, capability, scope, risk, revocation and target
binding remain independent gates.

## Production composition

Current source inventory confirms why the roles must be distinct:

- `http_baseline`: `url` string — complete endpoint selector;
- `tls_baseline`: `host` string + `port` integer — split host/port selector;
- `service_inventory`: `host` string + `ports` string — split host/port-set
  selector.

Those current production workers are LAB_ACTIVE, not new TARGET_ACTIVE
authority. They are shape evidence for the registry contract only.

The intended TARGET_ACTIVE order is:

1. resolve the trusted tool definition from the registry;
2. reject ambiguous ToolCall argument shape;
3. validate arguments against the trusted definition;
4. live-revalidate the exact authorization grant;
5. obtain destination-bearing argument names only from trusted definition
   metadata;
6. bind those destinations to the already-authorized asset/endpoint;
7. only then permit handler/retry/queue/DNS/socket/target I/O.

Failure at any step must produce zero handler and zero target/network I/O.

## Regression coverage in this branch

The standalone offline reference covers canonical role indexing, current
HTTP/TLS/service-inventory shape controls, empty metadata, caller-supplied
name-set rejection, list/tuple-subclass rejection, metadata subclass rejection,
duplicate names across roles, blank/padded/control-bearing names, enum type
confusion, role/kind mismatches, non-destination metadata isolation, and input
immutability.

## Ownership

- Issue #1093 owns this prerequisite contract.
- PR #107 remains the production executor/live-authorization source owner.
- PR #1092 remains the TARGET_ACTIVE argument-to-authorized-asset reference.
- PR #180 remains the LAB_ACTIVE argument-binding owner.
- PR #966 remains duplicate ToolCall-argument ownership.

This branch changes no production source and performs no target interaction,
DNS, socket operation, scan, dispatch, grant issuance or deployment.

## Promotion gate

The source owner must choose the production metadata shape and integrate it with
the real registry/executor. Promotion requires exact-head hosted and canonical
permanent VPS proof after that integration. This reference alone must never be
treated as permission to activate real targets.
