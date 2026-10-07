# ST5 evidence-collection persisted object exactness

Issue: #611  
Pinned parent: PR #64 at `f6f1c22bb16f3b6841c721087deba89953caf8c7`

## Contract

The strict evidence-collection handoff accepts JSON-shaped persisted state. A real
JSON decode can only produce exact built-in dictionaries, lists, strings,
integers and booleans. Direct Python callers must not be able to cross that
boundary with equal-looking subclasses that canonical persistence cannot emit.

Canonical `json.loads(request.to_json())` remains the green control.

The direct persisted-object parser must reject, without mutating caller state:

- top-level and item mapping subclasses;
- top-level and item schema-key string subclasses;
- the `items` list and item lineage-list container subclasses;
- string subclasses in request identities, lineage SHA-256 fields and
  `request_sha256`;
- string subclasses in item identities, `resolution_sha256`, fixed semantics,
  enum-valued fields and lineage-list entries;
- integer subclasses in `current_twin_version`, `twin_version` and
  `evidence_gap_count`.

Boolean authority fields are already checked by exact identity in #64 and are
therefore not duplicated in this type pack.

## Expected state on #64

The canonical JSON-decoded round trip is expected GREEN.

The subclass cases are expected RED on the pinned #64 head because the parser
uses broad `isinstance` checks, schema equality, Enum conversion and ordinary
integer/string validation. Equivalent-content Python subclasses can therefore
pass checks that real JSON persistence can never produce.

## Ownership and non-overlap

This branch is tests/docs only. It does not edit
`src/lightup/future_security_evidence_collection_request.py`; #64 remains the
strict handoff source owner and #62 remains the producer owner.

Keep separate from #136 persisted live consumption, #745 direct typed-object
construction, #318 snapshot isolation, #324/#331 parser input-purity, downstream
freshness/sufficiency consumers, scope authorization and all target-capable
execution.

## Safety

Persistence-integrity validation only. No network or DNS I/O, evidence
collection, capability/tool selection, target interaction, remediation/retest
execution, deployment, verdict creation or attack-path mutation.
