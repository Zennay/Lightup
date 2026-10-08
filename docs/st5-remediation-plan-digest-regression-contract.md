# ST5 remediation-plan digest offline regression contract

This additive test suite pins deterministic ST5 plan SHA-256 generation and ensures changing tenant, changeset, report, evidence, resolution, capability, action or item order changes the digest. It additionally pins planning classification outcomes for introduced, worsened, removed, improved and insufficient-evidence transitions, and requires unknown classifications to be rejected.

Run `PYTHONPATH=src python -m unittest tests.test_st5_remediation_plan_digest_reference -v` or via `unittest discover` on the canonical runner. This is an isolated reference regression of existing helpers, **not** an independently verified persisted or authenticated receipt, cryptographic signature, production authorization decision, or execution guarantee. No active network, target, capability, remediation or retest operation is performed. Existing source owners, adjacent evidence-remediation PRs, and production entrypoints are unchanged. Keep draft until exact-head CI and permanent VPS proof, review and integration.

## Enum coercion clarification

`AttackPathTransitionClassification` derives from `str` and `Enum`: the Python value `"introduced"` compares equal to the canonical member. It must **not** be used as a negative unknown-classification fixture. The negative regression instead supplies an unsupported value, and the test establishes only that unknown values fail closed. Tightening exact enum type identity is a separate production-owner decision, not implied by this reference suite.

## Complete lineage sensitivity matrix

Additional offline subcases pin the current/future twin identifiers and versions, all four upstream report digests, change/subject/resolution identifiers, transition classification, graph action, evidence-required flag, and all reference ID collections. A single-field mutation must alter the plan digest. These are deterministic serialization regressions; they do not authenticate evidence provenance or grant authority.

## Counts and input immutability

The reference suite additionally asserts the remediation/retest/evidence-gap counters and item membership affect the digest, and hashing leaves the supplied report and frozen item references unchanged. These low-level digest assertions do not replace producer-side consistency validation; a digest can bind inconsistent counters if the producer supplies them. The normal public builder remains responsible for rejecting inconsistent planning state.

## Independent canonical reconstruction

A separate test constructs a complete canonical ST5 JSON payload (including all three deny-authority flags, unresolved future semantics, and not-evaluated verdict) and independently computes SHA-256. It checks the production helper against the explicit fixture encoding without invoking any target or producing authorization. This catches accidental serialization key/flag changes, but does not prove an authenticated evidence ledger or retest outcome.
