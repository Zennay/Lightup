# ST5 remediation evidence-bundle fixed-string exactness

Issue: #579  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict persisted remediation evidence-bundle handoff accepts direct Python
objects as well as JSON text. Raw JSON can only produce exact built-in strings,
but direct object callers can provide `str` subclasses that compare equal to
canonical fixed metadata. A strict persisted boundary must reject that wider
runtime shape rather than accepting it by value.

## Required contract

The object parser must require exact built-in `str` values for:

- `schema_version`;
- item `classification`;
- `future_semantics`;
- `security_verdict`.

The canonical producer payload decoded with `json.loads` remains the green
control. Each adversarial case changes only the runtime type while preserving
the exact canonical text and all public digests. Rejection must not mutate the
caller-owned payload.

## Expected RED at the current parent

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`:

- schema version is compared by value;
- classification is passed directly into
  `AttackPathTransitionClassification(...)`;
- future semantics is compared to `"unresolved"`;
- security verdict is compared to `"not_evaluated"`.

Canonical-text string subclasses can therefore cross the persisted object
boundary even though JSON cannot produce them.

The source owner should reject non-exact scalar types before value comparison or
enum construction. Do not normalize or coerce.

## Collision boundary

This slice is distinct from:

- #400 classification/path presence semantics;
- #402 evidence-kind value semantics;
- #404 direct dataclass-construction invariants;
- #577 mapping-key identity;
- #578 container identity.

It does not modify #194/#60 production source or existing tests/docs, scope
authorization, target-capable execution, remediation/retest execution,
deployment, verdict creation or attack-path mutation.

## Safety

Persistence-integrity validation only. No model call, evidence collection,
network or target interaction, scanning, execution, remediation, retest or
deployment.
