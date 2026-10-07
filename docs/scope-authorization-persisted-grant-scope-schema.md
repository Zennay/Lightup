# Persisted authorization-grant scope schema integrity

Issue: #479  
Source owner: PR #142  
Exact acceptance base: `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Purpose

The execution resolver must treat the durable authorization-grant schema as untrusted input. Issuance persists JSON arrays and a known `RiskLevel`, so reloaded execution authority must not be reconstructed from malformed or shape-confused storage.

This branch reserves the acceptance contract only; it does not modify the active domain implementation.

## Contract

At execution resolution:

- canonical array-shaped assets/exclusions/capabilities and a known risk enum remain accepted;
- malformed persisted scope JSON is non-executable without parser exceptions escaping;
- object-shaped JSON is rejected even when its keys happen to equal valid assets or capability IDs;
- unknown persisted `max_risk` enum values are non-executable without exception leakage;
- validation does not rewrite or normalize durable state.

Object rejection is authorization-significant because `tuple(json.loads(object_json))` yields the object's keys. Without an exact array-shape check, a malformed object can masquerade as a valid allowlist.

## Acceptance cases

`tests/test_scope_authorization_persisted_grant_scope_schema.py` contains one canonical positive control plus six expected-RED durable-corruption cases:

1. malformed `assets_json`;
2. object-shaped `assets_json` keyed by the authorized asset;
3. malformed `allowed_capabilities_json`;
4. object-shaped `allowed_capabilities_json` keyed by a real capability;
5. malformed `excluded_assets_json`;
6. invalid persisted `max_risk`.

This is separate from #376, which owns issuance-time durable asset identity validation, and from #142's existing value-level risk/capability checks.

## Safety

Authorization narrowing only. No target interaction, scanning, exploit behavior, execution widening, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
