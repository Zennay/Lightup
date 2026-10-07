# ST5 remediation evidence-bundle lineage string exactness

Issue: #663  
Source owner: #194  
Mode: tests/docs-only expected RED

## Contract

Canonical persisted remediation evidence bundles are JSON-decoded data. Their
non-digest lineage/evidence string values therefore arrive as exact built-in
`str` objects. The direct object parser must reject equal-content Python
subclasses before those values can enter typed bundle state.

This acceptance slice covers:

- top-level `client_id`, `current_twin_id`, `twin_id`, and `changeset_id`;
- item `change_node_id`, `subject_node_id`, and `resolution_id`;
- one entry from each item string-list family:
  `current_attack_path_ids`, `effect_ids`, and `capability_ids`;
- nested evidence `evidence_id`, `run_id`, `capability_id`, and `kind`.

Canonical WORSENED producer JSON remains green. Rejected caller-owned input must
remain unchanged.

## Expected RED

At exact #194 head
`ec4b09f539289fbf3b497a534980323bd3c11bef`,
`_non_empty_string` and `_strict_string_tuple` use broad
`isinstance(..., str)`. Tuple materialization also preserves subclasses.
Because every adversarial value carries identical canonical text, existing
manifest/bundle digests remain valid and do not mask the runtime-type gap.

## Collision boundary

This is runtime-type fidelity only. It stays separate from:

- #577/#578 mapping-key and container identity;
- #579 fixed schema/classification/future/verdict strings;
- #580 SHA-256 strings;
- #581 count integers;
- #582 raw JSON text;
- #398 twin-version semantics/exact-integer requirement;
- #401 resolution/effect lineage semantics;
- #405 canonical change/subject/evidence/run identifier content;
- #407 canonical capability/current-path identifier content;
- #402 exact evidence-kind value semantics.

No #194/#60 source file is modified.

## Safety

Pure in-memory persisted-boundary acceptance. No evidence collection, model
invocation, target interaction, scanning, remediation/retest execution,
deployment, scope-authorization mutation, security verdict creation, or attack
path mutation. Keep this branch PR-less while permanent LightUp CI is occupied.
