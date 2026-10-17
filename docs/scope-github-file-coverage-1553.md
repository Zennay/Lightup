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

## W2 — installed ChangeSet adapter admission, still disconnected from production

New solely-owned `src/lightup/scope_github_coverage_adapter_1553.py` and
`tests/test_scope_github_coverage_adapter_1553.py` compose two separately
provided fictional views of the same GitHub file set: (1) strict claim
envelope and (2) bounded detailed file records. The real installed
`github_pull_request_changeset` is invoked **only after both views match
exactly** (file count, filename identity, SHA consistency, no partial
pagination or truncation), all records use exact supported statuses and
nonnegative bounded counters, rename paths are sane, and raw patches are
bounded UTF-8 text. A new tuple of built-in primitive records is supplied
to the existing adapter; the caller's original records are not modified.

This is source-integration *proof* in the separate isolated, opt-in lane, not
a change to `github_changes.py` or `cli.py`. No live GitHub data is
retrieved or authenticated; the reviewer remains REVIEW_ONLY even if all
synthetic claims agree. Any invalid metadata, source-adapter rejection,
duplicate or missing file exits HOLD **before a verdict can be promoted**.

Run:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_github_coverage_adapter_1553.py' -v
```

The standalone opt-in adapter CLI consumes only one JSON object with exact
keys `coverage` and `records` on stdin:

```sh
PYTHONPATH=src python -m lightup.scope_github_coverage_adapter_1553 --synthetic-only < fictional.json
```

It emits only fixed false authority fields, HOLD/exit2 or
REVIEW_ONLY/exit3, with at most a synthetic file count and number of
**inferred** signals. Neither output is approval. Dedicated subprocess tests
cover malformed input, duplicate JSON keys, invalid UTF-8, oversize data and
secret non-disclosure. The same new workflow now exercises both independent
30-method coverage tests (one known source-owner RED) and 26 installed-adapter
acceptance tests on Python 3.11 and 3.14. Actual final-head runs must be
inspected before any green claim.

Unchanged release requirements: authoritative authenticated GitHub full
pagination + stable base/head proof implemented and reviewed by #1538 source
owner; separate real client/operator consent with at-use revocation;
independent privacy/security review; original hosted and permanently
registered named-VPS CI on approved exact SHA; human GO. **NO MERGE OR DEPLOY.**

## W3 — complete unified-hunk evidence (synthetic only)

The independent real-source bridge additionally refuses missing patch text,
binary or empty patches, invalid/unknown hunk syntax and omitted content.
For ordinary UTF-8 GitHub unified hunks it checks **both**:
- The declared file additions/deletions equal the actual diff `+` and `-`
  lines across all supplied hunks (excluding context and special EOF marker).
- Each hunk's declared old/new span exactly matches the consumed old/new
  lines, including context lines. It rejects shortened hunks even when the
  sum of added/deleted lines is forged to match.

Unknown or combined Git diff formats, malformed Unicode and overlong patch
content are **HOLD**, not interpreted optimistically. Strictness is
intentional; this checker is not an authenticated Git parser. Validated
synthetic bytes can still differ from actual GitHub objects, so successful
results stay REVIEW_ONLY. No original code owner patch or auto-release hook
was introduced.

## W4 — ordered hunk coordinates and actual local Git regression

New acceptance tests first demonstrated **nine real original own-parser REDs** for
synthetic hunk overlap, reversal, impossible unchanged gaps and inconsistencies
between an `added`/`removed` GitHub status and the old/new file-side ranges.
The isolated gate now also checks:

- each next hunk follows the previous hunk in both old and new coordinates;
- the omitted old/new spans *between* hunks have equal lengths (unchanged
  regions must not silently hide modifications);
- nonempty spans cannot start at zero, and all coordinates/counts remain bounded;
- an `added` file has zero old-side lines; a `removed` file has zero
  new-side lines; contradictory deletions/additions result in HOLD.

The positive controls include a real, local, read-only
`git diff --no-index --no-ext-diff --no-textconv` from disposable synthetic
files, covering additions, deletions and distant two-hunk edits. A tampered
genuine Git hunk must HOLD before the installed ChangeSet source is called.
The tests use no network access, live assets, clients or credentials.

This still **does not** prove that caller-provided patch text matches the
authenticated GitHub changed-file objects. A fully consistent *fictional*
stream remains REVIEW_ONLY / exit 3 and never grants authority. Original
source-owner #1538, dual consent, permanent CI and human GO remain open.

## W5 — strict hosted proof receipt (no silent test losses)

The isolated `.github/workflows/scope-1553-github-coverage-offline.yml`
runs both owned regression modules on each Python 3.11 and 3.14 job and
**hard-fails** unless the exact observed execution receipt is:

```text
tests=85
expected_failures=1
failures=0
errors=0
skipped=0
unexpected_successes=0
```

Unlike only trusting the unittest exit code, this catches accidental file
discovery omissions, skipped tests and unexpected success of the one
deliberately unresolved original-source RED. It binds the proof to the
workflow's exact checked-out PR head SHA. A future legitimate source-owner
repair will require a conscious review and migration of the original-source
canary, not a silent declaration that this independent preview is release
ready. The receipt contains no customer input or raw patches.

The additional **CI gate is not production CI**, no permanent VPS runner or
actual grant authority is added or relaxed. All hard release HOLD conditions
remain.

## W6 — exact PR snapshot counts and 100-file page completeness (offline only)

New isolated owned module `src/lightup/scope_github_pr_pages_1553.py` accepts
a BEFORE PR snapshot, ordered 100-file REST page records, and an AFTER PR
snapshot. The module is a pure offline consumer of *normalized FICTIONAL
caller-supplied records*, never an HTTP/API client or authorization gate.

PR snapshots must have exact fields `version`, `synthetic_only`,
`repository`, `pr_number`, `base_sha`, `head_sha` and `changed_files`.
The two snapshots must exactly match, including base/head immutable SHAs,
repository and PR number, and changed-files count. This module conservatively
holds claimed totals outside 1–300; this is NOT GitHub's general page cap.

Each page must have `page`, `per_page=100`, `files`. The module derives
the exact page count and every page length from the PR's claimed
`changed_files`, enforcing strictly ordered, numbered and complete pages;
no missing 100-file middle pages, duplicates, wrong sizes, overcomplete pages,
or cross-page filename collisions. It never takes an independent arbitrary
expected count from the caller. Only fully consistent page sets are bridged
through our strict patch/hunk adapter and finally the **real installed**,
original source-owner `github_pull_request_changeset` (unchanged).

This **does not authenticate Github data**. An attacker who can forge all
normalized metadata can supply a consistent lie. Real owner #1538 must fetch
the two PR snapshots and every file page from the same trusted authenticated
GitHub client, verify immutable PR/repo identity and exact base/head,
handle paginated REST response provenance and API consistency, and HOLD on
missing/binary/oversize patches. No real online GitHub token, network,
production source, operator or grant is touched by this module.

Run isolated local tests:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_github_pr_pages_1553.py' -v
PYTHONPATH=src python -m lightup.scope_github_pr_pages_1553 --synthetic-pages-only < fictional-pr.json
```

The CLI accepts exact keys `before`, `pages`, `after`. It produces only
HOLD/exit2 or REVIEW_ONLY/exit3, **never exit0 or authority**. Fixed privacy
minimal fields do not echo filenames, SHA, patches or repository names. The
new 32-method suite covers 1/99/100/101/199/200/201/299/300 file boundaries,
missing/duplicate/short/reordered pages, SHA/count/identity drift,
malformed types and privacy. Dedicated hosted 3.11/3.14 CI now asserts
**exact 117 methods, one original-source expected RED, zero skips**.

Status: INCUBATE M3/M7 — DRAFT/HOLD. No merge, deploy, targets, real scans,
grants, handlers or release. Original-source owner integration, authenticated
real two-party consent plus revocation-at-use, independent security/privacy
review, permanent named-VPS CI and HUMAN GO still mandatory.
