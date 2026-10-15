# Synthetic Unicode/alias scope metadata review — DRAFT/HOLD

Issue: https://github.com/Zennay/Lightup/issues/1437
Posture: INCUBATE M3/M7 · PLAN/LAB ONLY. No active scope authority is granted.

This opt-in, offline **structural reviewer** addresses deceptive asset metadata. The real ScopeDefinition.allows_asset currently compares stripped/lowercased names; that is not a trust decision for Unicode confusables or URL-decorated representations. Only invented asset metadata may be passed to this tool. It does not modify ScopeDefinition, parse authorized production targets, contact DNS, query external services, inspect directories, load credential files, create permits, dispatch scans, alter production state or authenticate a client.

Usage: python scripts/review_scope_asset_unicode_20261015_offline.py --stdin-json < synthetic.json

Synthetic JSON must contain **exactly** three arrays: assets (1–32), excluded_assets (0–32), allowed_capabilities (1–32). Asset names are deliberately restricted to lowercase ASCII DNS-shaped opaque identities, 1–253 characters, labels 1–63 characters, no trailing dot and no xn-- prefix. IPv4-looking names are opaque strings here; no lab/private range determination is performed. Valid IPv6 or IDN assets can receive HOLD: this reviewer covers only a conservative subset, never a complete target parser. Capability identifiers use lowercase ASCII letters, digits and dash/underscore/dot separators; empty capability arrays (implicitly unrestricted in current model) are denied for even this structural review.

Strict JSON/UTF-8 max 8192 bytes rejects duplicate escaped keys, nonfinite numbers, extra fields, unexpected shapes and duplicate/intersecting asset sets. Input comes from local stdin file/pipe and has a two-second EOF deadline. REVIEW_ONLY exits 3 and contains only aggregate counts; HOLD exits 2 and has no counts. Both include six literal false flags: authorization_verified, permit_issued, dispatch_enabled, merge_approved, deploy_approved, release_approved. Nothing echoes input identifiers or approvals. Aggregate counts are not cryptographic anonymization; **never submit customer data**. Output transport is not cryptographically authenticated or fd-pinned.

Test: python -m unittest discover -s tests -p 'test_scope_asset_unicode_20261015_offline.py' -v

All test cases use fictional data. Host CI evidence applies only to the exact commit; it is NOT an installed ingress, registered self-hosted runner, client consent or production release proof. Before active work, original owners must verify actual approval request-to-grant provenance (#177), time-bound authorization (#347), per-dispatch revocation, exact asset/capability and network egress binding, installed deployment gates, independent privacy/security review and **explicit human authorization**. Do not merge, deploy, issue grants or scan targets on this basis.
