# Standalone LightUp incubation capability posture review

LightUp's current [Notion project policy](https://app.notion.com/p/3ed9e19ac9558117b639f2254fe0e165) is **INCUBATE M3/M7 · PLAN/LAB ONLY**, without active target interaction. Other [offline registry history comparison tools](scope-capability-registry-drift-offline-20261014.md) detect **changes between snapshots**, but two equally unsafe metadata snapshots may still compare equal. This independent opt-in audit checks the current **metadata's declared incubation posture**, not only whether it changed.

```bash
python3 scripts/review_scope_incubation_registry_offline.py
```

This calls the real local `get_capabilities()` registry through the strict canonical export verifier. It accepts **no arguments** or external manifest input and performs **no network or target activity**. The policy is intentionally conservative for this development phase:

- Every source capability must have canonical complete five-field metadata, with exact built-in `requires_explicit_activation = True`.
- The five predefined sensitive lab simulation capabilities — `ot-lab`, `wireless-lab`, `social-engineering-lab`, `human-layer-lab`, `physical-security-lab` — must be present and **LAB_ONLY**. Missing or reclassified entries get **HOLD** even if a change to DISABLED could be defensible in a future stage; such a change requires explicit policy review rather than implicit acceptance.
- Unsupported state identifiers, nonboolean flags, malformed/legacy manifests, source subtype spoofing and invalid Unicode metadata fail closed via existing canonical parser/exporter.
- Reports contain only canonical safe capability IDs, fixed violation codes and a canonical metadata fingerprint; they **never echo untrusted free text**.

`REVIEW_ONLY` exits **3**, `HOLD` exits **2**; **exit 0 is never emitted**. Every receipt hardcodes `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`.

## Scope of the evidence

This is an **optional standalone developer preflight**, not an implementation of the actual ToolExecutor, runtime activation/revocation, authorization, tenant scope, asset allowlist or customer consent. It **does not repair [issue #178](https://github.com/Zennay/Lightup/issues/178)**, which owns structural runtime capability-model validation, and it is not an authenticated checkout/provenance attestation. Do not connect REVIEW_ONLY to permission issuance or automated scanning.

The 18 focused synthetic and actual-registry unit regression methods cover current policy, activation downgrade, lab reclassification/missing records, parser confusion, result immutability, CLI nonzero exits and no free-text leakage. Python 3.11/3.14 exact-HEAD hosted CI and separate permanently registered VPS proof are distinct release controls; the Notion developer source-merge decision is not a production deploy.
