# ST5 remediation direct-constructor integration gate

This tests/docs-only gate sits above the completed constructor-hardening stack
and proves the original and revised remediation planning chains share one
non-executable direct-construction contract.

## Covered chains

Original remediation chain:

`authoring request -> remediation text proposal -> review request -> review`

Revised remediation chain:

`revision request -> revised proposal -> revised review request -> revised review`

For all eight top-level artifacts, the gate proves:

- the directly constructed object serializes and round-trips through its strict
  persisted parser without normalization drift;
- strict structural parsing remains deliberately weaker than live validation:
  after evidence-ledger SHA drift, the unchanged final review still parses
  structurally while its complete live-lineage validator rejects reuse;
- every code/tool/execution/target/retest/deploy/attack-path authority field is
  fixed false, and integer lookalikes such as `0` are rejected rather than
  accepted as false booleans;
- every strict JSON parser rejects duplicate primary-digest keys before JSON
  last-value-wins behavior can normalize them;
- every strict JSON parser rejects unknown top-level fields rather than silently
  widening its schema;
- persisted artifact structures remain bounded to lineage/provenance/review
  metadata and contain no raw source, payload, credentials, target arguments,
  authorization references, patches, commands, or tool-argument keys;
- `future_semantics` remains `unresolved`;
- `security_verdict` remains `not_evaluated`;
- changing the artifact's primary canonical digest without rebuilding the
  artifact fails closed;
- remediation text acceptance exists only on the final approved review objects.

The nested authoring item also keeps both `remediation_required` and
`future_state_retest_required` as exact booleans.

## Constructor-hardening stack

Promotion order is intentionally linear:

1. #250 — revised-remediation revision-loop non-execution invariant.
2. #252 — revised-remediation direct authority/lifecycle guards.
3. #254 — original remediation direct authority/lifecycle guards.
4. #255 — nested authoring-item direct structural integrity.
5. #256 — top-level authoring-request direct structural integrity.
6. #258 — original proposal/review-request/review direct structural integrity.
7. #261 — revised proposal/request/review direct structural integrity.
8. #263 — this cross-chain integration gate.

Do not skip parents or promote from hosted proof alone. Each promoted exact head
still requires the canonical self-hosted `vps-bb300bba` LightUp proof once the
runner is restored.

This gate adds no model call, target interaction, tool execution,
remediation/retest execution, deployment, future-state resolution, verdict
creation, or attack-path mutation.
