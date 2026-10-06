# ST5 remediation authoring-request exact capability coverage

Issue: #413

This tests/docs-only acceptance is based on exact active #198 head `7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Gap

The strict #198 parser checks only that each evidence `capability_id` occurs in the enclosing item `capability_ids`. It does not reject item capabilities that have no evidence reference.

The live producer chain is exact-set bound. ST4 requires the fresh evidence capability set to equal the transition-resolution capability set; #60 carries that validated set into the remediation evidence bundle; #196 copies it unchanged into the remediation-authoring request.

## Acceptance contract

- a real WORSENED producer request remains a green control and proves exact capability coverage;
- adding an extra item capability with no supporting evidence is rejected;
- the forged payload recomputes a matching public `request_sha256`, so stale-digest rejection cannot satisfy the contract;
- no automatic union or normalization is permitted.

The forged case uses the strict parser directly, not live validation.

## Non-overlap

Distinct from #409/#410 (canonical capability/path identifier shape and ordering) and #411/#412 (canonical evidence kind). Exactly one regression module and one document are added. No production source or existing tests/docs are modified.

## Safety

Persistence-integrity proof only. No model invocation, code/config generation, target interaction, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
