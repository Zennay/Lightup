# Non-authorizing capability registry drift review

An **opt-in, offline developer review** to detect release-to-release changes to the capability registry. This does not install a gate in the production executor and is not evidence of customer consent, ownership, revocation status or runtime authorization. No network activity, API access, scans, grants or approval are performed.

## Input

Two regular local UTF-8 JSON manifests representing explicitly chosen baseline and candidate versions:

```json
{"capabilities":[{"capability_id":"web-baseline","state":"planning","requires_explicit_activation":true}]}
```

Each manifest is bounded to 32 KiB / 128 distinct canonical ASCII IDs. All three fields are required; unknown keys, duplicate JSON keys or IDs, weird numeric bools, invalid state names and nonregular/symlinked files fail closed. Order does not affect canonical SHA-256 metadata fingerprints. The metadata baseline is chosen by the human reviewer; the tool **does not prove repository, manifest, author or grant provenance**.

Run: `python3 scripts/review_scope_capability_registry_offline.py BASELINE.json CANDIDATE.json`.

`REVIEW_ONLY` (exit **3**) means these *declared metadata* snapshots match. `HOLD` (exit **2**) means drift or invalid input; changed identifiers are reported without a synthetic promotion/demotion recommendation. **Neither returns exit 0.** All receipts carry `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`.

## What still requires independent checks

Trusted immutable signed/referenced registry baselines, source-owner review, separately attested customer and tenant scope, current valid operator consent and revocation checks, exact-head CI (hosted + permanently registered VPS), independent security/privacy review and human release decision. Never connect this comparison result to `ActivationGate`, `ToolExecutor` or actual target interactions. Project remains **INCUBATE M3/M7 · PLAN/LAB ONLY**.
