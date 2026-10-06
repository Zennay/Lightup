# Persisted evidence collection request consumer

The ST5 evidence collection request is intentionally non-authoritative: it
describes unresolved evidence gaps and fresh-evidence requirements, but does not
grant collection or execution authority.

For persisted input, strict object parsing alone is not enough. The request must
also still match the current remediation/retest lineage and StateStore.

`load_and_validate_future_security_evidence_collection_request` composes both
requirements:

1. JSON text rejects duplicate object keys recursively;
2. JSON/object input passes through the exact request parser; and
3. the parsed request is immediately rebuilt against live plan/report/preview,
   transition-resolution, RunContext and StateStore lineage.

A caller receives no parsed request unless all three boundaries pass.

## Safety semantics

Successful validation preserves the existing fail-closed contract:
`collection_authorized=false`, no capability or tool is selected, no tool call
is created, target interaction stays false, remediation/retest execution stays
false, deployment stays false, attack-path mutation stays false, future
semantics stay unresolved and no security verdict is claimed.

This consumer performs no target interaction and introduces no execution
authority.
