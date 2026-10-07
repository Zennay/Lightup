# ST5 remediation-text proposal persisted object type exactness

Issue #621 isolates a persistence-type boundary above strict remediation-text proposal handoff #209 at exact parent head `38c40d112751728c238dcf5d7ab556079528c38e`.

## Contract

The canonical direct-object control is `json.loads(proposal.to_json())`. JSON decoding produces exact built-in mappings, strings, integers and booleans. The programmatic `future_remediation_text_proposal_from_dict` path must reject equivalent-content Python subclasses rather than normalize them into trusted typed state.

The acceptance regression requires exact built-in types for:

- the top-level proposal mapping;
- every top-level schema key;
- request, bundle, content and proposal SHA-256 values;
- schema version, provider/model provenance, remediation content, future semantics and security-verdict strings;
- the positive `item_count` integer.

Canonical JSON-decoded producer state must continue to reconstruct the exact proposal. Rejection must leave caller-owned persisted input value-equivalent to its pre-call snapshot.

## Separation from existing owners

This branch changes tests/docs only and does not modify #209 source. Raw JSON text typing, content/model normalization, parser/live-validation atomicity, producer behavior and scope authorization stay in their existing lanes.

## Safety

This proof only narrows persisted type fidelity. It does not invoke a model, interact with a target, generate/apply code or configuration, execute tools, execute remediation/retests, deploy, create a security verdict or mutate attack paths.

## Expected state

The exact #209 parser currently relies on broad `isinstance` checks and value equality for these programmatic object/scalar boundaries. The acceptance module is intentionally expected RED until the #209 source owner absorbs exact built-in type checks.
