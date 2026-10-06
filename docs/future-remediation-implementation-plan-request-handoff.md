# Future remediation implementation-planning request handoff

This boundary persists and reloads the request to create a later remediation
implementation plan. It remains a planning-only contract.

The parser requires the exact schema, canonical SHA-256 values, strict
primitive types, non-empty reviewer provenance and fixed fail-closed authority
flags. Duplicate raw JSON keys are rejected before last-value-wins decoding.

After structural validation, the request is rebuilt from the strict live
accepted-review chain. Any drift in evidence, remediation proposal, review
request, verifier review, reviewer provenance or item count invalidates the
persisted request before follow-up use.

A valid handoff still means only
`implementation_planning_requested=true`. It does not mean an implementation
plan exists, and it does not authorize code/config changes, tool calls, target
interaction, remediation execution, future-state retest, deployment or
attack-path mutation. Future semantics remain `unresolved` and the security
verdict remains `not_evaluated`.
