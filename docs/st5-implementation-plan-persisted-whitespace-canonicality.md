# ST5 persisted implementation-plan whitespace canonicality

This acceptance slice distinguishes producer-side text normalization from persisted-integrity validation at the strict initial implementation-plan handoff.

## Contract

The implementation-plan producer may intentionally trim bounded model output **before** the canonical plan digest is created. Once that canonical artifact is persisted, the strict handoff must not trim newly introduced surrounding whitespace and reconstruct the old value.

For programmatic persisted-object input, extra surrounding whitespace in any trim-normalized text field is tampering and must fail closed while the original stored digest remains unchanged. Covered fields are:

- `provider_id`, `model_id`, and `summary`;
- plan-item `plan_item_id`, `intent`, `verification_intent`, and `rollback_intent`;
- non-empty `assumptions` and `unresolved_questions` entries.

The canonical producer payload remains valid. Rejection must leave caller-owned persisted input unchanged.

## Why this is distinct

Issue #277 deliberately proves producer normalization before hashing. Issue #601 owns Python subclass exactness. This slice instead covers exact built-in strings whose persisted bytes were changed **after** the canonical digest existed.

The current handoff calls `strip()` inside `_bounded_text` before constructing the typed plan and recomputing `plan_sha256`. A whitespace-mutated persisted value can therefore collapse back to the original canonical value and make the unchanged digest verify, hiding storage tampering.

## Safety and ownership

Acceptance-only and expected RED above exact strict-handoff head `f8da50cae174d372be20ccef4a203a766db63618`.

Exactly one regression module and this contract document are added. There are zero production/source changes, no model invocation, target interaction, scanning, remediation/retest execution, deployment, verdict creation, or attack-path mutation. The #237 source owner retains implementation ownership.
