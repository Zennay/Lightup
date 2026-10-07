# ST5 remediation evidence-bundle digest scalar exactness

Issue: #580  
Parent: #194 exact head `ec4b09f539289fbf3b497a534980323bd3c11bef`

## Purpose

The strict persisted remediation evidence-bundle handoff validates the textual
shape of SHA-256 digests. For direct Python-object input, that is not sufficient
to reproduce the JSON input model: a `str` subclass can carry canonical digest
text while remaining a non-canonical runtime scalar.

## Required contract

The persisted object parser must require exact built-in `str` values for:

- top-level `report_sha256`;
- top-level `plan_sha256`;
- top-level `bundle_sha256`;
- item `resolution_sha256`;
- item `evidence_manifest_sha256`;
- evidence-reference `sha256`.

The real JSON-decoded producer payload is the green control. Each adversarial
case changes only runtime type, preserving all 64 lowercase hexadecimal
characters and all digest equality. Rejection must not mutate caller-owned
input.

## Expected RED at the current parent

At #194 head `ec4b09f539289fbf3b497a534980323bd3c11bef`,
`_canonical_sha256` accepts `isinstance(value, str)`. Therefore a canonical
digest carried by a string subclass passes textual validation and subsequent
digest comparisons.

The source owner should reject non-exact scalar types before textual SHA-256
validation. Do not coerce or normalize.

## Collision boundary

This slice is distinct from #398 version semantics, #404 direct typed-object
construction, #405/#407 identifier canonicality, #577 mapping-key identity,
#578 container identity and #579 fixed metadata strings. It does not modify
#194/#60 production source or existing tests/docs.

## Safety

Persistence-integrity validation only. No model call, evidence collection,
network or target interaction, scan, execution, remediation, retest, deployment,
verdict creation or attack-path mutation.
