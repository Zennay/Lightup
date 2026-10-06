# Future remediation text revision-proposal handoff

This boundary persists and reloads revised remediation prose without treating it
as accepted text or action authority.

## Strict proposal integrity

The handoff requires the exact schema, canonical lowercase SHA-256 values,
non-empty provider/model provenance, bounded non-empty prose, an exact content
digest and the exact canonical revision-proposal digest. Serialized JSON rejects
duplicate keys before normal decoding.

The revised proposal must keep remediation_revision_proposal_created true while
remediation_accepted and every code, tool, execution, target, retest,
deployment and attack-path authority flag remain false.

## Live lineage

A structurally valid persisted revised proposal is not enough. Before reuse the
handoff also validates the strict live revision request, independent review,
prior proposal and all underlying evidence lineage. The persisted revised
proposal must bind the exact current revision-request, review, prior-proposal
and prior-content digests.

This validation does not re-invoke the remediation-advisor model.

## Stop line

The artifact remains unaccepted defensive prose. A later independent review is
required before the prose can be considered accepted, and acceptance still
must not imply code generation, tools, target interaction, execution, retest,
deployment, attack-path mutation or a security verdict.
