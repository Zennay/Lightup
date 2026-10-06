# ST5 strict retest-request parser input purity

This tests/docs-only child of #359 proves that the strict
`future_security_retest_request_from_dict` parser treats caller-owned
persisted dictionaries and nested lists as read-only input.

## Successful parsing

The regression uses real #359 payloads for every supported future-state retest
classification:

- `introduced`;
- `worsened`;
- `improved`;
- `removed`.

For each payload it snapshots:

- the complete caller-owned value graph;
- JSON key/list ordering;
- every recursively reachable dict/list object identity.

Parsing the exact same object twice must return the exact typed request both
times while all caller-owned snapshots remain unchanged.

The parsed request still carries only planning semantics:
`execution_allowed=false`, `target_interaction_allowed=false`,
`deployment_authorized=false`, `attack_path_mutation_allowed=false`,
`future_semantics=unresolved`, and `security_verdict=not_evaluated`.

## Rejection purity

Two rejection depths are covered independently.

An exact-schema violation is rejected before deeper semantic parsing, and the
caller-owned object remains byte/order/identity stable across repeated failure.

A canonical-shape request with a stale `request_sha256` traverses the full
strict parser and reaches semantic digest verification. Repeated digest
rejection must again leave the exact caller-owned object unchanged and return a
stable failure message.

This prevents normalization, sorting, popping, replacement or partial mutation
from becoming an observable side effect of either successful parsing or
fail-closed rejection.

## Safety boundary

This proof adds no model call, StateStore mutation, target interaction, tool
execution, remediation/retest execution, deployment, verdict creation or
attack-path mutation.
