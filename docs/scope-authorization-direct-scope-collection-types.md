# Direct ScopeDefinition collection type contract

LightUp treats a directly constructed `ScopeDefinition` as authorization state. The dataclass annotations alone are not a runtime security boundary: tuple subclasses can override iteration or membership, and string subclasses can override normalization/equality behavior.

## Required invariant

Before a direct scope can be used as authorization state:

- `assets` is an exact built-in `tuple`;
- `excluded_assets` is an exact built-in `tuple`;
- `allowed_capabilities` is an exact built-in `tuple`;
- every member of all three collections is an exact built-in `str`;
- malformed direct construction fails closed rather than normalizing or accepting protocol-substituted behavior.

Canonical exact tuple/string inputs keep their existing semantics.

## Why this matters

Without exact runtime collection boundaries, caller-controlled subclasses can change authorization decisions without changing the apparent stored values. Examples include a tuple whose iterator yields an allowlisted asset while storing a different asset, or a tuple whose membership operator claims an unlisted capability is present.

These are in-memory authority-spoofing risks. The invariant is deliberately narrower than persisted-scope reconstruction and narrower than issuance-time domain validation.

## Acceptance proof

`tests/test_scope_authorization_direct_scope_collection_types.py` contains:

- a GREEN canonical control;
- RED acceptance for `assets` tuple subclasses;
- RED acceptance for `excluded_assets` tuple subclasses;
- RED acceptance for `allowed_capabilities` tuple subclasses;
- RED acceptance for string subclasses in each collection.

The acceptance branch is intentionally tests/docs only. Production repair belongs to the ScopeDefinition source owner and must not be absorbed here while that source surface is actively owned elsewhere.

## Safety boundary

This contract only narrows in-memory authorization parsing. It performs no DNS or network I/O, target interaction, scanning, handler dispatch, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
