# Semantic signal evidence integrity

Issue #862 narrows the ST2 `SemanticChangeSignal.evidence_refs` typed-object boundary.

## Gap

Semantic change signals are inferred, evidence-linked hints that are included in the canonical `ChangeSet` digest and later projected into Security Twin facts.

Previously `validate()` required only that `evidence_refs` was non-empty. A caller could therefore supply a list, tuple subclass, non-string member, string subclass, blank reference or duplicate lineage and have it participate in ChangeSet identity before any downstream model rejected it.

## Canonical contract

`SemanticChangeSignal.evidence_refs` now requires:

- an exact built-in `tuple`;
- at least one member;
- exact built-in `str` members only;
- non-blank members;
- unique members.

Validation never trims, stringifies, sorts, deduplicates or otherwise repairs caller input.

The existing ST2 semantics are unchanged: semantic signals remain inferred only, confidence bounds remain unchanged, and the signal must still reference a valid repository path in its containing ChangeSet.

## Producer compatibility

The structured-change producers already construct evidence references as tuples. This validation therefore rejects only producer-impossible typed states and does not change canonical structured-document enrichment.

## Non-overlap

This slice does not change repository path handling, ChangeSet object/uncertainty validation, structured document parsing, Security Twin primitive validation (#858/#859), ST3 materialization/effect evidence (#860/#861), target-capable code, deployment, verdict or attack-path mutation behavior.

## Safety

Immutable ST2 evidence-lineage narrowing only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
