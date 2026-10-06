# ST5 remediation/retest strict parser caller-input purity

This tests/docs-only child proves that the #190 dictionary parser is
side-effect-free with respect to the caller-owned persisted payload it reads.

## Distinct boundary

This contract is narrower than nearby integrity work:

- #320 proves the typed result is detached from later caller mutation;
- #323/#329 prove input purity for earlier evidence-remediation parsers in the
  #98 ancestry;
- #352 proves typed live-validation input atomicity after parsing;
- this proof covers the #190 remediation/retest plan dictionary parser itself.

No production source or existing #190 test is changed.

## Successful parsing

For all five canonical ST4 classifications, a real remediation/retest plan is
serialized and decoded into a caller-owned dictionary. Before parsing, the test
records:

- a deep value snapshot;
- byte-stable JSON using the existing dict/list ordering;
- every nested caller-owned dict/list container identity.

The same dictionary is parsed twice. Both typed results must equal the real
producer plan, while the caller-owned value, ordering, and recursive container
identities remain exactly unchanged.

This proves the parser does not sort, replace, pop, normalize, or otherwise
rewrite caller input in place.

## Rejection purity

Two failure depths are covered independently:

1. an exact-schema violation with an added nested caller-owned object;
2. a canonical-shape payload whose `plan_sha256` is changed so rejection occurs
   only after the parser has traversed and reconstructed the typed plan.

Each exact rejected object is submitted twice. Both attempts must return the
same failure message while value, ordering, and every nested dict/list identity
remain unchanged.

## Safety boundary

Successful parsing and rejection retain the existing stop line:

- `execution_allowed=false`;
- `deployment_authorized=false`;
- `attack_path_mutation_allowed=false`;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

This is pure in-memory persistence-integrity proof. It performs no StateStore
mutation, evidence collection, model invocation, target interaction, tool
execution, remediation/retest execution, deployment, verdict creation, or
attack-path mutation.
