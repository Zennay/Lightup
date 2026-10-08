# Scope authorization: duplicate tool-parameter schema (RED acceptance)

**Phase:** M7/ST5, offline fail-closed hardening. **Owner boundary:** add-only test and contract; do not edit `src/lightup/ai/orchestration.py` (owned by #107), policy #100, grant storage, registry owner #156, or parallel #966 duplicate *call arguments* work.

## Invariant

At `ToolRegistry.register` admission, a `ToolDefinition.parameters` schema must have unique parameter names, independent of parameter kind or required flag. A duplicate name makes argument validation ambiguous: `ToolDefinition.validate_arguments` currently builds `known = {p.name: p for p in self.parameters}` (last wins) while sequential validation still iterates both definitions. Reject ambiguous definitions **before registry mutation**. This is distinct from duplicated entries in an incoming `ToolCall.arguments` (#966).

The two negative controls use a registered capability (`web-baseline`), ANALYSIS interaction, and inert handlers: one conflicting kind pair, one identical-kind pair with different requiredness. Both require `OrchestrationError`, zero registration side effects, and no handler execution. The test is deliberately RED against current main; do not weaken assertions to make CI green.

## Verification and handoff

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_auth_duplicate_tool_schema_red_20261008.py' -v
```

Expected before production fix: two failures because duplicate names are accepted. Implementation owner should enforce exact unique parameter-name admission, preserve normal existing tool registration, test schema cloning/mutation if applicable, and only promote after exact-head green CI plus permanent self-hosted runner proof.

No credentials, DNS/network access, real target, discovery, scans, active execution, deployment, grant issuance or authority widening are involved.
