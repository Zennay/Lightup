# ST5 isolated retest-request snapshot isolation

This tests/docs-only sibling of exact PR #52 proves that a produced
`FutureSecurityRetestRequest` cannot be rewritten through data snapshots
returned to callers.

## Deterministic export

For real producer requests covering `introduced`, `worsened`, `improved`
and `removed`, repeated `to_json()` output must be byte-for-byte stable.

Repeated `as_dict()` calls must also be value-equal but independently
allocated at the top level and for nested request-item dictionaries.

## Mutation isolation

The regression deliberately mutates one caller-owned `as_dict()` snapshot,
including:

- client and request-digest lineage;
- nested change identity;
- nested evidence and capability lineage;
- aggregate requested capability/evidence collections;
- request completion and isolated-future-state lifecycle markers;
- execution, target-interaction, deployment and attack-path authority flags;
- future semantics and security verdict.

None of those mutations may affect a second independently returned snapshot,
the immutable typed request, or later canonical JSON output.

This means an exported planning snapshot cannot become a backdoor for
rewriting request authority or lineage.

## Safety boundary

The source request remains:

- `request_complete=true`;
- `isolated_future_state_required=true`;
- `execution_allowed=false`;
- `target_interaction_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No evidence collection, target interaction, tool execution, remediation/retest
execution, deployment, verdict creation or attack-path mutation is added.
