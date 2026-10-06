# ST5 classification-reviewer preflight direct-construction integrity

Issue #337 hardens the typed `FutureSecurityClassificationReviewerPreflight` boundary itself. The canonical #322 producer and live validator already rebuild reviewer eligibility from the strict evidence-remediation lineage, but a frozen dataclass can still be instantiated directly or changed through `dataclasses.replace()`. This slice makes contradictory in-memory state fail at construction time instead of relying on a later handoff or live validator.

The constructor now requires the exact schema version; canonical identity strings and lowercase SHA-256 lineage; tuple-backed, non-empty, sorted, unique candidate evidence/capability identifiers; an exact `AttackPathTransitionClassification` member; distinct canonical sufficiency-verifier and classification-reviewer identities; the exact `operator` reviewer role; exact reviewer-independence and eligibility booleans; false classification/action-authority state; unresolved future semantics; and a not-evaluated security verdict.

The stored `preflight_sha256` is recomputed from the full typed state (excluding the digest field itself). Regression tests deliberately recompute a matching digest for forged authority/future-state payloads before direct construction, proving that semantic stop-line checks — not merely stale-digest rejection — prevent authority widening.

This is a sibling of the strict serialized handoff work in #326 and the producer snapshot-isolation work in #335. It does not modify those files or change the canonical producer flow.

Safety remains PLAN-LAB ONLY: no classification decision is made, no evidence is collected, no model or verifier is invoked by the new checks, no target/tool/remediation/retest/deployment action is introduced, and no future security verdict or attack-path mutation is materialized.
