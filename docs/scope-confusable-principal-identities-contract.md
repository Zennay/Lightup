# Scope authorization: Unicode-confusable principal identifiers (offline acceptance)

Status: proposed M7/ST5 fail-closed contract, **not** an implementation or permission to activate targets.

## Risk
Identity-bearing strings (tenant, reviewer, issuer lineage, approval/request revision, authorization ID) must never acquire authority by display similarity, case folding, Unicode normalization or trimming. For example, ASCII `tenant-a` and Cyrillic-a `tenant-а` look similar but represent different byte sequences; `reviewer` and `reviеwer` (Cyrillic e) are not interchangeable. Full-width, compatibility, combining-mark and zero-width variants have similar ambiguity. Human-facing presentation may normalize for display, but authority comparisons must not use that presentation.

## Proposed acceptance invariants
1. Bind authorization to issuer-controlled, immutable canonical identifiers, not arbitrary claims or rendered labels. Prefer opaque generated IDs for tenant, reviewer, request revision, approval and grant lineage.
2. A string obtained by case folding, NFKC/NFC normalization, trimming invisible characters, or substituting confusables must not match an independently issued identity by accident. Reject noncanonical user-supplied identity before lookup, or compare verified opaque IDs; never silently rewrite into a privileged principal.
3. Keep both trusted internal ID and untrusted display label separate. Display label, approval notes and AI output are never role/provenance evidence.
4. Reissue/reapproval is mandatory if a material identity or immutable request revision changes; do not mutate an old approval's binding.
5. Deny on mixed script, noncanonical input, type confusion or conflicting canonicalization across layers. Log a minimal denial category without reflecting potentially sensitive raw identifiers.
6. Evaluate these checks at the real dispatch boundary, even if a UI or API already validated its input. Scope, risk, reviewer and current revocation checks remain independently mandatory.

## Offline matrix
The accompanying JSON fixture contains visually similar identity pairs and exact-match controls. The fixture test checks shape and expectations only; it neither invokes the executor nor proves production enforcement. Owners of #107 and approval-source integration must decide a concrete canonical ID scheme and add real boundary tests; do not change their production files in this lane.

## Release constraints
No DNS, socket, scan, target, capability handler or deployment is used. Promotion requires source-owner integration, exact-head hosted and permanent VPS proof, and explicit review. Passing these structural tests alone does not authorize active assessment.
