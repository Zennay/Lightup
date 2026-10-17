# Scope #1553 — offline GitHub compare changed-file coverage

**Posture:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This reviewer cannot authorize a user, asset, scan, handler, grant, merge, deployment or release. It cannot authenticate GitHub API metadata.

## Independent observation (source-owner PR #1538)

At fixed source-owner head `f9358ac4d21ca722e0ce1dc3d885aa45024fa9ba`, `github_pull_request_changeset(..., files=..., too_large=False)` accepts a non-empty supplied file list without independently seeing `changed_files` or pagination. If a caller accidentally supplied one of two files, the missing security-relevant change would not be represented. That is a **synthetic ingestion-completeness gap**, not proof of an authorization bypass. Other owners handle path-identity (#1541), policy floor (#1543), patch UTF-8 (#1545), Git raw status (#1547), and branch dependency topology (#1549); this issue does not modify their files.

## Implementation

`src/lightup/scope_github_file_coverage_1553.py` is a separate, **unwired**, standard-library-only checker. It accepts strictly versioned JSON on stdin with:

- exact `version = LIGHTUP-FICTIONAL-GITHUB-FILE-COVERAGE-V1` and `synthetic_only = true`;
- exact lower-case 40-character hexadecimal expected and observed base/head SHAs, both pairs equal and base different from head;
- a caller-declared `expected_changed_files` in 1–300, matched by a bounded list of unique synthetic filename-only file records;
- explicit `has_next_page = false` and `truncated = false` booleans;
- no unknown fields, duplicate JSON keys, non-finite numbers, invalid UTF-8, oversized input or ambiguous file record forms.

A non-conforming envelope produces a single opaque `HOLD` status, exit **2**. A syntactically coherent envelope produces **REVIEW_ONLY**, exit **3**. Exit **0 never occurs**; all authority/effect flags remain false. Input is never echoed (including file paths or SHA values). There is no network, Git, external file or database access and no third-party dependencies.

Example (offline fictional data only):

```bash
printf '%s' '{"version":"LIGHTUP-FICTIONAL-GITHUB-FILE-COVERAGE-V1","synthetic_only":true,"expected_base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observed_base_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_changed_files":1,"files":[{"filename":"src/example.py"}],"has_next_page":false,"truncated":false}' |
PYTHONPATH=src python -m lightup.scope_github_file_coverage_1553 --synthetic-only
# REVIEW_ONLY JSON, process exit 3: NOT APPROVAL
```

Tests: `PYTHONPATH=src python -m unittest -v tests.test_scope_github_file_coverage_1553` (or `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_github_file_coverage_1553.py' -v`). Includes one **deliberately still original-source expected RED** showing adapter-level incomplete intake; do not count it as fixed.

## Known limits and owner handoff

**Consistency is not completeness.** The `expected_changed_files`, claimed pagination flags, and expected/observed SHAs are fictional/untrusted in this module. Malicious matching metadata cannot be authenticated offline; REVIEW_ONLY is a *request for further review*, never a PASS. Stronger source-owner integration must fetch and authenticate the PR metadata from GitHub, iterate the authoritative changed-files endpoint with full pagination, bind immutable base/head SHA at both reads, compare the exact received count and status, and fail closed before any inferred verdict/report persistence. GitHub compare endpoints may cap arrays; cross-check the PR's authoritative `changed_files`, not merely a caller's `too_large` boolean.

**Release HOLD remains** pending owner source integration, independent security/privacy review, distinct real client + operator authorization with at-use revocation, exact-head hosted + permanent named VPS CI, and explicit human GO. No new source-owner code, existing runner workflow, target, grant, dispatch or release is touched by this isolated branch.
