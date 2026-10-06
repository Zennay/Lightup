# ST5 implementation-plan strict parser caller-input purity

This tests/docs-only invariant proves that the strict persisted remediation
implementation-plan dictionary parser is side-effect-free with respect to the
caller-owned object graph it reads.

## Boundary

The contract is intentionally separate from adjacent implementation-plan work:

- nested-JSON integrity proves recursive duplicate keys fail closed;
- snapshot-isolation proves parsed/produced typed snapshots detach from later
  caller mutation;
- this contract proves parsing itself does not rewrite, normalize, reorder, or
  replace caller-owned dictionaries and lists.

No implementation-plan producer, handoff source, existing handoff regression,
review/revision branch, scope policy, or target-capable code is changed.

## Successful parsing

A real bounded implementation plan is serialized and decoded to a caller-owned
dictionary. Before parsing, the regression records:

- a deep value snapshot;
- byte-stable JSON preserving the existing dict/list order;
- every recursive caller-owned dict/list container identity.

The exact same object is parsed twice. Both typed results must equal the real
producer plan while the caller-owned value, ordering, and recursive container
identities remain unchanged.

The parsed artifact retains the planning-only stop line:
`implementation_plan_created=true`, while code/tool/execution/target/retest/
deployment/attack-path authority remains false, future semantics remain
`unresolved`, and the security verdict remains `not_evaluated`.

## Rejection purity

Two failure depths are covered:

1. an exact-schema violation containing an extra nested caller-owned object;
2. a canonical-shape payload whose nested plan-item intent is changed, allowing
   the parser to traverse and reconstruct the typed plan before canonical digest
   validation fails.

Each rejected object is submitted twice. The failure must be deterministic and
the original caller-owned value, JSON ordering, and recursive dict/list
identities must remain exactly unchanged.

## Safety

This is pure in-memory persistence-integrity proof. It performs no model
invocation, StateStore mutation, target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
