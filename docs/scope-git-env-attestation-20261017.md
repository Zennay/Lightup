# Clean-main ownership correction (2026-10-17)

This reviewable copy is an independently isolated cherry-pick of **only these six owned files** directly onto original LightUp main `e73b7445c87ad239bdb03c50a99078ef93163b02`. The preceding `chatgpt/scope-auth-git-env-fence-20261017-0115` branch inherited 22 files from a *different* literal-control worker; draft PR #1529 was closed without merge as soon as that was detected. Historical entries below describe the previous branch's isolated experiments, NOT the ancestry, commit count, reviewable diff, or CI evidence of this new branch. This clean branch is the only eligible scope Git-env review head. DRAFT/HOLD; no merge/deploy/authority.

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
unchanged pinned parent. Exactly six *new*, exclusively owned paths are
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

## W4 — conservative interpreter and loader override HOLD

In addition to arbitrary `GIT_*` names, the self-contained reviewer now
conservatively holds on explicit process-loader overrides:
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`,
`DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `PYTHONPATH`,
`PYTHONHOME`, `PYTHONSTARTUP` and `PYTHONINSPECT`. Even *empty*
values are not treated as environment proof. No optional user-provided
module or library is loaded to test these names. A custom environment
Mapping throwing ordinary Python exceptions also produces HOLD rather
than a traceback. These changes address twelve newly reproduced
synthetic test failures (11 negative-input failures and one error).

**Important limitation:** shared libraries and module search paths can
already have been processed *before* this Python reviewer starts.
Therefore a REVIEW_ONLY result is not proof of trusted process startup,
absence of shell hooks, safe HOME/XDG config or immutable future env.
Only a non-authorizing negative policy report is emitted. The work is
still isolated from production and any release authority.

## W5 — hosted setup-python profile, preserving strict HOLD

The W4 loader check exposed a genuine hosted-CI incompatibility:
GitHub-hosted `actions/setup-python` supplies `LD_LIBRARY_PATH`
pointing to its own `/opt/hostedtoolcache/Python/3.x.y/x64/lib`.
Run #38991024082 legitimately failed both interpreters at the *initial
environment reviewer* (no tests executed in those failing jobs).
Logs established the exact Python 3.11 and 3.14 runner values.

The exception is a tightly bounded, purely **lexical** recognition of
that setup-python configuration: literal Linux runner; own push event/ref;
40-character lowercase SHA; identical `pythonLocation` and
`Python_ROOT_DIR`; a strict Python 3.11 or 3.14 x64 toolcache location;
and `LD_LIBRARY_PATH` equal to that location plus `/lib`. All other
loader overrides, extra search-path segments, malformed origins, wrong
branch, pull-request refs, or absent fields remain HOLD.

These environment strings are **self-reported**, not cryptographically
attested. A malicious actor able to set the whole environment could
imitate the profile. The result still conveys only `REVIEW_ONLY` with
all four authority flags false; it does not assert trusted binary/library
provenance, clean worktree, client consent or any permission. Real
source-owner authorization repairs and human release GO remain blocked.

## W6 — reject deceptive mapping implementations

An adversarial unit test demonstrated that a custom `Mapping.items()` could
report no entries while `__iter__` and `__getitem__` exposed `GIT_DIR`.
The old duck-typed reviewer would incorrectly return REVIEW_ONLY. An
overridden `dict.items()` has the same problem. The new strictly offline
admission accepts only an **exact Python dict snapshot** or the actual
`os.environ` object; any subclass or custom Mapping receives HOLD.
This tests the integrity of an in-memory representation only, not the
origin or continuing immutability of a process environment. It does
not confer consent or execution authority. DRAFT/HOLD remains.

## W7 — real disposable Git file mode acceptance

The byte-level Git tree validator now has an independent realistic fixture.
A temporary repository is initialized with precisely the six separately
owned paths as ordinary tracked Git files; its actual `git ls-tree -rz`
output passes the validator. The same synthetic repository then records
one path as a **symlink** (mode `120000`) and later as an **executable**
(mode `100755`); both snapshots are correctly rejected. The temporary
repository is deleted at test end and never touches a LightUp target,
production source, another worker or live authorization state.

The complete isolated suite now contains **23 tests** (16 process-environment
and 7 Git-tree acceptance cases) on Python 3.11/3.14 when the final exact-head
workflow completes. This is only diagnostic non-authorizing evidence.

## W8 — future runtime override families fail closed

The previous explicit list of interpreter/dynamic-loader overrides left
unrecognized variables (e.g. `LD_BIND_NOW`, `DYLD_FALLBACK_LIBRARY_PATH`,
`PYTHONPYCACHEPREFIX`, `PYTHONUSERBASE` and `PYTHONBREAKPOINT`) silently
passing into a REVIEW_ONLY diagnostic. New fixture tests reproduced **16
negative-case failures** across standalone and hosted-looking environments
before the fix. The lightweight reviewer now rejects any key beginning
with `GIT_`, `LD_`, `DYLD_` or uppercase `PYTHON`, even with empty
values. The existing exception is deliberately restricted to precisely
the previously documented GitHub setup-python `LD_LIBRARY_PATH`
toolcache profile and does NOT exempt other LD_* names or paths.

This remains a **negative environment string review**; environment keys
are supplied by a caller, can change later, and do not constitute binary,
repository, consent, grant or release attestation. The hosted toolcache
profile is not cryptographic provenance. DRAFT/HOLD persists.

## W9 — prevent PATH-shadowed Git evidence

An offline regression with a disposable fake executable named `git`
placed before `/usr/bin` in `PATH` reproduced a false process identity:
the original validator called `subprocess.run(["git", ...])` and read the
fake program's arbitrary output. The validator now calls only the
known absolute `/usr/bin/git` executable on Linux. Both the zSSH
Ubuntu checkout and GitHub's Ubuntu hosted runner use this path. The
regression now proves that a forged leading PATH entry cannot redirect
the Git evidence process.

This path pinning does **not** cryptographically authenticate the binary,
prevent altered libraries, guarantee safe inherited Git config or turn
review-only evidence into release consent. The hosted path is a deliberate
platform constraint; missing `/usr/bin/git` yields HOLD, not a fallback
to `PATH`. No real Git config or production application was changed.

## W10 — disable repository-configured fsmonitor execution

A second disposable real-Git regression proved a more severe implicit
side effect: merely invoking `git status --porcelain` inside a synthetic
repository with `core.fsmonitor` set to a local hook **executed an
external script**, even though the validator only requested read-only
evidence. The test first reproduced a failing condition against this
branch's proof wrapper. It now runs `/usr/bin/git -c
core.fsmonitor=false` for every evidence command, overriding local,
global and system fsmonitor configuration without modifying any Git
settings or project files.

In the test, the hook creates a marker only inside the disposable
temporary fixture; after the fix the marker is absent during the guarded
Git command. This proves the specifically configured fsmonitor route
is disabled. It does not prove that every possible Git extension,
binary, library or configuration is harmless, nor does it authorize a
real scan or release. Production remains entirely untouched.

## W11 — assert reported Git worktree is this checkout

A disposable real-Git fixture shows that `git config core.worktree
/path/to/foreign` redirects `git rev-parse --show-toplevel` away from
the repository used to invoke Git. Without checking the resolved root,
a `git status` assertion may examine another worktree's files. The
own, non-authorizing Git evidence validator now demands the exact
absolute `--show-toplevel` output match its own script checkout path.
A synthetic full-script test reproduced the previous erroneous PASS for
a forged external root before the fix. Both forged and real temporary
configuration cases are now covered by new tests.

This is a narrow path-identity guard; it does not establish filesystem
trust, prevent symlinks outside the own checkout, prove Git binary
provenance, or confer any scan or release authority.

## W12 — silent Git diagnostics required for offline proof

A separate synthetic `main()` regression reproduced another misleading
green: a Git command reporting a warning/error diagnostic to stderr while
exiting 0 could still satisfy the original branch proof. The check now
requires *every* evidence subprocess (status, HEAD, worktree root,
merge-base, diff, tree) to finish with exit 0, exact byte output types
and **zero stderr bytes**. A successful exit accompanied by diagnostic
output becomes `scope_env_owned_tree=HOLD`, not PASS.

This is a conservative lab evidence integrity condition. It may reject
benign Git warnings, intentionally requiring human investigation rather
than treating them as authorization, and never claims all underlying
Git operations or repository contents are trusted.


## W53–W55 — local Git filter execution and nested submodule fence (2026-10-17)

Source-confirmed offline risk: even read-only `git status --porcelain` can
execute a repository-configured `filter.<driver>.clean` for tracked paths
selected by `.gitattributes` when Git must compare equal-length modified
content. Disabling `core.fsmonitor` alone did **not** close this execution
surface. This does not establish an external exploit of LightUp.

The separately owned, unwired `scripts/check_scope_git_env_tree_20261017.py`
now reads tracked paths with `ls-files --cached -z` and reads all selected
`filter` attributes through `check-attr -z --stdin filter` **before** calling
`git status`. It requires exact unambiguous NUL triplets, a bounded set of
distinct tracked paths, no Git warnings, and `unspecified` filter for every
tracked entry. Any selected filter, malformed response, oversized listing or
nonzero status causes HOLD **without executing status**. Ordinary attributes
such as `text eol=lf` remain allowed. This deliberately conservative proof
may HOLD on legitimate Git LFS repositories and is not a general Git sandbox.

The actual `git status` evidence command also passes
`--ignore-submodules=all` to avoid recursively walking untrusted nested Git
repositories while reading branch-local evidence. The installed-submodule
security posture is **not** attested by the helper; it simply refuses to
interrogate submodules.

Synthetic isolated regressions: a disposable local repo with a configured
external clean-filter and an equal-length modified tracked file proves
unprotected Git status runs the marker script; protected status returns HOLD
and leaves the marker untouched. Additional negative tests check malformed
Git responses; a separate non-filter attribute control remains green.
This work modifies only this branch's previously owned scripts/tests/docs.
It does not modify runtime permissions, deployment or release gates.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Git-history evidence is
review-only, not real client consent, at-use revocation or authorization.
No scan, grant, handler dispatch, merge or deployment is permitted by it.


## W56–W59 — bounded Git evidence subprocess I/O (2026-10-17)

Prior to this update, the isolated Git-tree checker used
`subprocess.run(..., capture_output=True)`, which fully buffered arbitrary
Git stdout/stderr **before** examining their sizes. A maliciously large
repository response could cause unnecessary memory pressure, even when
the eventual review would HOLD. The new `_git_raw` uses selector-driven
bounded pipes. It checks stdin type/size before process creation (max
262,144 bytes), accumulates no more than 786,432 bytes stdout or
16,384 bytes stderr, has a 15-second total deadline, and kills/reaps
the Git subprocess on timeout or oversized streams. Unexpected output
or exceptions fail closed in the existing generic, non-authorizing
`scope_env_owned_tree=HOLD` path.

Additional true disposable Git tests cover exact upper stdin with a
hash-object digest, no-spawn oversized input, greater-than-cap 786,433-byte
Git blob stdout, a 25,000-byte Git alias stderr fixture, and ordinary
status after both deliberate overflow conditions. No actual LightUp
targets, original project worker processes, deployments, credentials,
permissions or source-owner paths are touched.

As with the earlier filter preflight, this helper is an opt-in Git
evidence *diagnostic* only; even PASS is not authorization, proof of
provenance across administrative trust boundaries, verified consent or
release permission. Full original hosted CI, permanent named VPS,
source-owner security fixes and independent human GO remain required.

## W60–W61 — terminate detached Git descendants on evidence timeout (2026-10-17)

A rejected Git child can exit before its descendants release inherited
stdout/stderr. Killing only the original process PID would leave such
helpers running beyond the bounded evidence deadline. Git now runs in a
dedicated process session and the failure handler sends SIGKILL to the
**entire process group** before reaping the Git parent. This cleanup is
restricted to the freshly launched helper session, not existing workers
or any production scanner processes. A synthetic disposable Git alias
starts a delayed shell child; shortening only the test-local deadline
proves the child starts but never reaches its delayed filesystem marker
after HOLD. This is not permission to execute Git aliases or real
untrusted shell commands in regular validation.


## W62–W65 — ambiguous 'filter=unspecified' bypass sealed on clean-main draft

Git's regular `check-attr -z --stdin filter` returns the literal value
`unspecified` **both** when no filter is selected and when the checked-out
attributes explicitly select `filter=unspecified`. The latter is a valid
Git driver name: configuring `filter.unspecified.clean` in a disposable
repository makes unguarded read-only `git status` execute the selected
shell fixture against an equal-length modified tracked file. Thus the
original offline filter preflight could incorrectly return REVIEW_ONLY
for a selected executable driver. This was reproduced with only
temporary fictional Git repositories; no real targets were touched.

The dedicated, unwired `_tracked_files_have_no_filters` now calls
`check-attr --all -z --stdin` for the exact tracked paths. Unlike the
single-attribute query, `--all` returns triplets only for **present**
resolved attributes, including literal `filter=unspecified`, attributes
expanded from `[attr]` macros, `.git/info/attributes`, and the configured
global `core.attributesFile`. The parser accepts only bounded exact
NUL triplets from known tracked paths; duplicates, malformed names or
values, unknown paths, and every selected `filter` attribute cause HOLD
before `git status`. Ordinary `text`/`eol` attributes remain allowed.
This is fail-closed diagnostic evidence, not a production repair,
authority, real provenance, or consent.

Dedicated source-integrated real Git tests prove red-to-green for the
explicit `unspecified` driver, info/global sources, and a macro-expanded
driver, with an actual external marker in **unprotected disposable**
controls and no marker when protected. The helper never runs its
protected `git status` against a selected filter. Additional mocked
bad-triplet cases prove malformed output always HOLD.


## W74–W79 — ignored worktree cannot masquerade as a clean source tree (2026-10-17)

The original `git status --porcelain -z --untracked-files=all`
deliberately **omits files covered by .gitignore, .git/info/exclude
and core.excludesFile**. A disposable Git checkout containing tracked
`.gitignore` and ignored untracked `sitecustomize.py` returned literally
empty status despite a potentially interpreter-relevant file. The
isolated checker formerly treated that empty status as a clean source
checkout. This is a source-proof discrepancy, **not an observed exploit
of LightUp's live target-authority runtime**.

The owned and unwired Git attestation helper now calls
`git ls-files --others --ignored --exclude-standard -z` before the
original Git status; **only exact empty successful stdout/stderr**
passes. Hidden `.py`, bytecode caches and any other ignored content
HOLD. Tests use real disposable Git repositories with `.gitignore`,
`.git/info/exclude`, and custom global exclusion files, plus mocked
malformed Git results. The checker does not delete ignored files,
change global Git configuration or make a grant.

To keep the mandatory before/after checkout attestation compatible
with this stricter guarantee, the separately owned Python3.11/3.14
hosted workflow no longer runs `compileall` (which writes ignored
`__pycache__`). It syntax-compiles four own sources in memory,
and uses `python -B -m unittest` so tests don't generate bytecode.
All checks remain bounded, read-only and on the existing fixed
clean-main scope branch.

This does not prove absence of malicious metadata in the `.git`
directory, external PYTHON startup attacks or tampering by a
privileged actor. Its receipt can **never** authorize execution,
consent, a scan or release. Scope source-owner security fixes,
authenticated client and operator consent plus at-use revocation,
full original CI, registered permanent VPS and explicit human GO
remain independent prerequisites.


## W80–W86 — exact owned working-file bytes defeat Git index misdirection (2026-10-17)

A separate real, temporary Git repository showed that
`git update-index --assume-unchanged owned.py` lets Python source on disk
change while `git status --porcelain -z` remains empty and `git ls-tree
HEAD` still reports the pristine committed Git blob. Likewise, a
`skip-worktree` flag can conceal a missing locally checked-out file.
Git commit/manifest validation alone does **not** prove that the bytes
actually available to an interpreter match the committed source.

The additive, unwired `_worktree_blobs_match_head` now verifies **all
six** exclusively owned, new review files against the exact Git blob
SHA-1 object bytes (`blob {len}\\0{raw}`) recorded by `ls-tree HEAD`.
It refuses absent, symlinked, nonregular, oversized (>1 MiB per file),
unexpected or mismatched files. Intermediate symlinks are rejected,
reads are bounded to 1 MiB + 1 byte, regular-file descriptors are
re-checked after opening with `O_NOFOLLOW`/`O_NONBLOCK` where
available, and any exception fails closed. Both the original checked
Git manifest and the actual worktree content must match, in addition
to the ignored-file and clean-status gates. A checkout with altered
index bits must HOLD even if `git status` reports clean.

Disposable Git regressions demonstrate ordinary correct source PASS,
unmodified HEAD with altered `assume-unchanged` source HOLD, missing
`skip-worktree` source HOLD, plus missing/symlinked/oversized source
HOLD. This remains strictly negative source review evidence: **not**
a production security gate, tamper-proof runtime isolation, real
client/operator permission, an original CI pass, or release approval.
No production LightUp code, VPS runner, grant, handler or scanner is
modified by this work.


## W87–W89 — canonical index flags required even when bytes currently match (2026-10-17)

A clean and byte-identical tracked source file may nevertheless have
Git's `assume-unchanged` or `skip-worktree` bit set. The previous raw
worktree-blob verifier would correctly reject **existing** divergence,
but it could not warn about those hidden future-source-change masks
while a file still happened to match the committed SHA-1.

The separate, read-only index-fence now examines `git ls-files -v -z`
for **exactly the six scope-owned tracked paths** and requires literal
canonical `H path\\0` for every path. Lowercase assume-unchanged
(`h`), skip-worktree (`S`), duplicate/missing/unexpected paths,
nonzero Git exit or any diagnostic output produce HOLD. Real
disposable Git regression toggles both flags while content is still
unchanged and proves each transitions from PASS to HOLD and back
after removing the flag. The already proven raw file-byte check
remains independently mandatory; neither check is an authorization
gate or proof against a privileged concurrent attacker.

No merge, deploy, real asset scan, grant, handler execution or
release. Existing project-phase, source-owner, privacy, consent,
original full hosted and named permanent VPS proof gates remain open.


## W90–W92 — child Git environment isolation (2026-10-17)

The offline source-review checker runs `/usr/bin/git` even for read-only
operations. A normal `subprocess.Popen` without an explicit `env`
would forward ambient `GIT_*` Git config/worktree redirection,
`LD_*`/`DYLD_*` dynamic-loader keys, and `PYTHON*` startup keys
to each Git child. Main's earlier fail-closed `GIT_*` check addresses
one entrypoint only; it does not by itself protect direct helper calls.
The isolated helper now builds a subprocess-only environment copy
that drops *all* those four prefix families before every new Git
process. The parent environment and any installed global or system
settings are not changed. The absolute executable pathname and
before-status filter, ignored-file and per-file Git blob fences remain
mandatory.

Executable synthetic tests create only temporary Git repositories,
intercept the newly spawned subprocess's argument envelope, assert
that mock `GIT_DIR`, `GIT_CONFIG_COUNT`, previously unknown Git
overrides, `LD_PRELOAD` and Python/DYLD startup keys are absent, and
verify that normal Git status/version still succeeds. These tests
never load an actual external library or contact an external target.
They also cover not-yet-known future override-prefixed names, while
allowing an unrelated GitHub event marker to pass through.

This cannot retroactively undo loader effects on the already-running
Python interpreter and cannot certify all global/system Git metadata.
Its output is non-authorizing diagnostic evidence, **not** a permit,
customer consent, operator approval, deployed guard, runtime scanning
policy, complete original-project CI success, or a release decision.


## W93–W96 — descriptor-anchored Git blob reads prevent parent symlink races (2026-10-17)

The earlier exact-owned worktree blob hash verifier checked each parent
path for symlinks and then opened the final file using an absolute
pathname. On a concurrently modified checkout, an intermediate
directory could theoretically be swapped for a symlink between that
check and `open`; a leaf-only `O_NOFOLLOW` does not protect an
intermediate directory component.

The isolated source reviewer now first opens the checkout root as a
directory and descends through **each** owned path component with
directory-relative file descriptors (`os.open(..., dir_fd=...)`).
Every directory component requires `O_DIRECTORY|O_NOFOLLOW`;
the final regular file requires `O_NOFOLLOW`. On platforms lacking
either primitive, the review returns HOLD rather than performing
a less constrained pathname open. Descriptor handles are closed in
all paths, file metadata and raw bytes remain bounded (1 MiB max
per file), and the canonical Git blob hash check still applies.

A real disposable repository fixture verifies a valid nested source
file PASS; a deterministic swap of its parent directory into a
symlink between the pre-check and anchored open returns HOLD; and
restoring the original directory returns PASS. A separate synthetic
test checks that absent `O_DIRECTORY` or `O_NOFOLLOW` fails closed.

These diagnostics remain offline and non-authorizing. There is no
claim of a race-free snapshot against privileged writers who can
change file contents after validation, nor any permission to deploy,
scan, grant, dispatch a handler or release LightUp.


## W97–W99 — isolated interpreter for every hosted review step (2026-10-17)

After proving the Python 3.14 suite and the exact-head offline tree
checker pass in a separate full-history zSSH disposable checkout under
`python -I -B`, the branch-owned no-secrets Python 3.11/3.14 workflow
now runs its environment receipt, original SHA/tree preflight, source
compilation, both unittest suites, and post-test receipts/tree
preflight using `python -I -B` throughout. The `-I` interpreter
option disables user-site packages, PYTHON environment influence and
automatic current-directory insertion into import search paths.
The `-B` option prevents ignored bytecode from contaminating the
Git ignored-file evidence fence. Workflow-structure tests pin exact
isolated commands and reject the earlier weaker test form.

This change hardens only the isolated review runner and does not
grant privileges, validate a permanent registered VPS runner, modify
production source, trust external inputs, resolve preexisting source
REDs or authorize a scan. Global/interpreter and privileged-runner
integrity remain external assumptions to be independently reviewed.
