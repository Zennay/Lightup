# LightUp · separate offline Git environment attestation

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Not an authorization service.**

## Why this isolated check exists

The pre-existing scope review worker already hardened the committed-tree,
worktree-byte, ignored-file and index-flag proofs on its own branch. That lane
is actively owned elsewhere and has not been modified by this work.

Git also accepts process environment variables that can redirect which
repository, object database, index, worktree or config its commands read.
Examples include `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_COMMON_DIR`,
`GIT_CONFIG_COUNT`, and `GIT_OBJECT_DIRECTORY`. A clean-looking Git status
alone is not evidence that such overrides were absent.

## Isolated, non-authorizing implementation

- `scripts/scope_git_env_attestation_20261017.py` scans the supplied mapping
  for *any* `GIT_*` key, including future unknown names and empty values.
  Present override, malformed mapping, or excessive entry/key/value count
  returns **HOLD**; otherwise **REVIEW_ONLY**.
- Fixed JSON receipts always include `authorized=false`,
  `consent_verified=false`, `dispatch_allowed=false`,
  `release_allowed=false`. CLI exit 2 is merely review-only and
  exit 3 means HOLD; exit 0 is never used.
- No environment value is emitted. No Git command, repository edit, Python
  code execution from inputs, network request, target discovery, scanner,
  handler, grant, or deployment is performed by the reviewer.
- The eight owned synthetic unit tests cover hostile and harmless
  environments, process exit codes, malformed inputs, bounded enumeration,
  sensitive value non-echo, and rejected `--grant` arguments.
- Dedicated GitHub-hosted workflow on **this branch only** runs the
  isolated tests for Python 3.11 and 3.14. The workflow checks exact push
  SHA and admits only four add-only files since pinned parent
  `7b9142bb9e9d5403d7a3e41914edddef4511c8a8`. It deliberately does
  not touch the active review worker's workflow or sources.

## Limits and deployment boundary

A REVIEW_ONLY record is a diagnostic *negative authority* statement, not a
safe-runtime verdict: it does not prove a trustworthy executable search
`PATH`, absence of LD_PRELOAD, trustworthy binaries, signed Git history,
branch equivalence, correct original project CI, named self-hosted runner,
or a two-party client/operator consent. Other processes can mutate the
environment after review; this check is not wired into production.
Nothing may be merged, deployed, activated, scanned, granted, dispatched or
released without separate source-owner remediation, security/privacy review,
verified consent and explicit human GO. Four open source-expectedFailures
in the other lane are NOT repaired by this report.

## Extended fixture and evidence continuity (W2)

The test family now has **12 named tests**, including a real but wholly
disposable Git demonstration: two repositories are created under a temporary
directory in the isolated branch's worktree. A committed tracked file in one
repository is changed; its native porcelain status shows that change. With
`GIT_DIR` and `GIT_WORK_TREE` redirected to the other clean repository,
the *same command in the dirty repository* reports no modifications.
This is not an exploit of a live LightUp target or a scan; temporary
repositories and files are deleted automatically by the test harness.

A read-only AST check also pins the limited source imports and bans explicit
system/exec/network/file-write calls in the tiny reviewer. This is a
diagnostic lexical invariant, not proof against reflection or arbitrary
interpreter compromise. The dedicated hosted workflow now demands fixed,
non-authorizing REVIEW_ONLY JSON **before Git proof commands and again
after the own tests**; a differing status, unauthorized field, output or
exit code fails CI. These checks neither replace the active worker's
original tree proof nor confer any authorization. Source owners and
release review remain independent. **DRAFT/HOLD.**

## W3 — exact owned Git file-mode boundary

A separate own-path offline validator
`scripts/check_scope_git_env_tree_20261017.py` replaces the CI workflow's
former pathname-only inline script. It reads Git's NUL-delimited
`diff --name-status --no-renames` and `ls-tree -r -z` output for the
unchanged pinned parent. Exactly five *new*, exclusively owned paths are
allowed and required, each with a Git `100644 blob` and a lowercase 40-digit
object ID. Symlinks (`120000`), executable entries (`100755`), submodule
gitlinks (`160000`), tree entries, duplicates, malformed wire bytes and
unrelated changes fail closed. There are no production changes.

Six new adversarial tests supply fabricated delta/tree blobs and simulate
the script's exact-head `push` environment through mocked Git subprocesses.
They check normal PASS and wrong SHA, `GIT_DIR` override and symlink HOLD.
These fixtures do not scan or contact targets, and cannot grant authority.
The dedicated hosted workflow runs the proof **before and after** the
isolated Python 3.11 / 3.14 tests.

**Proof limits:** a matching Git tree shape alone does not guarantee
worktree bytes, index flags, ignored files, signed provenance or at-use
environment stability. The other concurrently owned branch handles its own
independent worktree/index attestation and remains unchanged. This report
never authorizes LightUp execution or deployment. Continue DRAFT/HOLD.
