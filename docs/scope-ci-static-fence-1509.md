# LightUp canonical CI static release fence — #1509

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. No merging, deployment, real targets, scans, grants or handler dispatch. This is **not** release readiness.

## Goal
A separate scope-authorization worker can check that the unchanged, original `.github/workflows/lightup-ci.yml` still contains the original permanent VPS hostname assertion, required self-hosted labels, strict checkout and credential boundary, Python 3.11 and 3.14, and all unit/integration/offline canary steps. This avoids falsely interpreting a silently softened YAML workflow as equivalent safety evidence.

## What was implemented
- `scripts/scope_ci_static_fence_1509.py` is a *pure*, stdlib-only in-memory function. It receives exact built-in bytes, rejects subclasses, text, unknown sizes, non-ASCII, duplicated/missing/out-of-order critical lines, CRLF, NUL and any other byte drift. It returns an immutable generic `HOLD` or `REVIEW_ONLY` receipt with all four `authorized/consent_verified/dispatch_allowed/release_allowed` flags false.
- The selected exact original `main` commit is `e73b7445c87ad239bdb03c50a99078ef93163b02`; its `.github/workflows/lightup-ci.yml` SHA-256 baseline is `961a5e6356598ae258a5cff605b634c92be7ac177297f210432641e418076750` (Git blob `a737f28309e321f98316ae1c7cab8953579be0e8`). This developer-selected digest is a **change-detection hint, not provenance/authentication**. Even a benign comment modification yields `HOLD` until independently reviewed and explicitly re-pinned.
- `tests/test_scope_ci_static_fence_1509.py` checks original bytes, every critical control removed, runner/hostname/permissions/checkout/credential/matrix/integration/canary downgrades, every single-byte XOR mutation, injected YAML jobs, wrong types/bytes subclasses, and blocked I/O/process/network hooks.
- Dedicated **opt-in, no-secrets GitHub-hosted** `.github/workflows/lightup-scope-static-fence-1509.yml` runs only these ordinary tests on Python 3.11 and 3.14. It does not change the canonical runner/workflow, and passing this isolated hosted job cannot count as the permanent VPS runner evidence.

## Important blind spots / required gates
An internally consistent *maliciously chosen new snapshot* could have its hash replaced by a bad actor; the tool is not a signature or trusted auditor. The function does not parse/execute YAML and never queries current GitHub jobs. `REVIEW_ONLY` says only **same bytes as the original reviewed workflow**, not that the workflow ran. It cannot prove CI completeness, registered machine identity, confidentiality or real consent.

Issue [#1144](https://github.com/Zennay/Lightup/issues/1144) remains the operator's registered permanent `vps-bb300bba` proof; [#1309](https://github.com/Zennay/Lightup/issues/1309) owns read-only *live* CI run metadata; [#1499](https://github.com/Zennay/Lightup/issues/1499) owns source AST review; [#301](https://github.com/Zennay/Lightup/issues/301) retains the original source-owner date test. This branch modifies none of their paths. Full original hosted suite on exact head, genuine registered permanent VPS jobs, original source fixes, separately independently verified client **and** operator consent, revocation at execution use, independent security/privacy review and explicit human GO remain mandatory.

Local: `python -m unittest discover -s tests -p 'test_scope_ci_static_fence_1509.py' -v`. No scans, target/network actions or policy/grant decisions are performed.
