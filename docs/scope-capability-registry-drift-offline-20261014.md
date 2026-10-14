# Non-authorizing capability registry drift review

An **opt-in, offline developer review** to detect release-to-release changes to the capability registry. This does not install a gate in the production executor and is not evidence of customer consent, ownership, revocation status or runtime authorization. No network activity, API access, scans, grants or approval are performed.

## Input

Two regular local UTF-8 JSON manifests representing explicitly chosen baseline and candidate versions. Legacy three-field records remain readable, while current exporter records also bind the capability's human-readable name and description:

```json
{"capabilities":[{"capability_id":"web-baseline","state":"planning","requires_explicit_activation":true,"name":"Web baseline","description":"HTTP/TLS configuration review"}]}
```

Each manifest is bounded to 32 KiB / 128 distinct canonical ASCII IDs. Exactly the three legacy or five current fields are required; partial metadata is refused. Names and descriptions must be nonblank bounded NFC Unicode without hidden control/formatting characters; descriptions are included in the canonical fingerprint and must trigger HOLD on semantic change, including upgrade from a legacy manifest. Quoted braces/brackets do not count toward structural nesting. Unknown keys, duplicate JSON keys or IDs, weird numeric bools, invalid state names and nonregular/symlinked files fail closed. Order does not affect canonical SHA-256 metadata fingerprints. The metadata baseline is chosen by the human reviewer; the tool **does not prove repository, manifest, author or grant provenance**.

Run: `python3 scripts/review_scope_capability_registry_offline.py BASELINE.json CANDIDATE.json`.

The CLI requires **two distinct physical regular files**, not merely two paths: the same file or any hardlink to its inode returns `HOLD`. Identical bytes in two independently stored regular files remain `REVIEW_ONLY` only, with all authority flags false. Symlinks, directories and FIFOs are rejected and cannot block review. These are local file-identity checks, **not** proof of trustworthy baseline provenance.

`REVIEW_ONLY` (exit **3**) means these *declared metadata* snapshots match. `HOLD` (exit **2**) means drift or invalid input; changed identifiers are reported without a synthetic promotion/demotion recommendation. **Neither returns exit 0.** All receipts carry `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`.

## Review which fields changed (read-only)

When metadata differs, the receipt includes both `changed_capabilities` (sorted canonical capability IDs) and `changed_fields`, a map from each ID to exact field labels. Labels are confined to `added`, `removed`, `state`, `requires_explicit_activation`, `name`, and `description`. Multiple fields are reported in stable order. A legacy three-field to full five-field metadata transition reports `name` and `description` drift; it never silently upgrades trust.

**No name/description text or customer content is echoed in receipts**: only canonical ID and these six fixed labels. Malformed manifests remain `HOLD` with empty `changed_fields`, identical reviewed snapshots remain `REVIEW_ONLY` with empty details. Every receipt still hardcodes authorization, permits, execution, merge and release as false. This is explanatory developer metadata, not consent evidence, a signed manifest, or automatic release eligibility.

## Generate the current local candidate

The optional `python3 scripts/export_scope_capability_registry_offline.py > CANDIDATE.json` serializes **actual local** `get_capabilities()` metadata using strict builtin model, enum, boolean, name and description identity. It rejects duplicate/noncanonical IDs, non-builtin boolean flags and malformed registries, then writes only the strict manifest JSON to stdout. The exporter deliberately exits **3 even on successful export**, or **2 for invalid data**; its successful shell exit is not zero. Compare a separately saved trusted, human-selected baseline against the newly generated candidate, rather than a copy against itself. Output provenance depends entirely on the checkout and reviewer: the exporter does **not** attest the repository commit or grant authority.

The original reviewer regressions, 12 in-repository registry exporter regressions, 17 semantic name/description regressions and six local file-identity regressions cover field identity, metadata drift, unsafe input, canonical ordering and CLI safety; hosted 3.11/3.14 and permanent registered VPS evidence must be gathered per final SHA.

## What still requires independent checks

Trusted immutable signed/referenced registry baselines, source-owner review, separately attested customer and tenant scope, current valid operator consent and revocation checks, exact-head CI (hosted + permanently registered VPS), independent security/privacy review and human release decision. Never connect this comparison result to `ActivationGate`, `ToolExecutor` or actual target interactions. Project remains **INCUBATE M3/M7 · PLAN/LAB ONLY**.
