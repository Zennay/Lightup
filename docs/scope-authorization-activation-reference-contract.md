# Canonical activation-reference contract

Issue: #498

## Boundary

This contract is limited to `ActivationPolicy.activation_reference` when `mode is ActivationMode.AUTHORIZED`.

It does not change runtime activation behavior, add adapters, enable target interaction, or modify `scope.py`. It is intentionally separate from legacy `Authorization` provenance, permit capability binding, activation-mode typing, and permit target binding.

## Required invariant

An authorized activation policy may carry authority/audit lineage only when `activation_reference` is an exact built-in `str` whose trimmed content is non-empty.

The implementation must therefore fail closed for:

- `None`, empty, or whitespace-only references;
- truthy non-string values such as integers, booleans, collections, and arbitrary objects;
- `str` subclasses whose overridden methods can substitute a different identity during validation.

Canonical non-blank built-in strings remain accepted unchanged.

## Expected current-state proof

Current `main` performs a truthiness-only check. The acceptance regression is therefore expected to be red only for the new malformed-reference cases while the canonical control remains green.

## Safety

Offline validation only. No DNS, network I/O, target interaction, scanning, execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation is introduced. ST5 remains PLAN-LAB ONLY.
