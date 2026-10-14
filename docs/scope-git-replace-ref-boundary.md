# Git replace-ref identity ambiguity — scope review acceptance (#1314)

**Posture:** LightUp INCUBATE M3/M7, **PLAN/LAB ONLY, DRAFT/HOLD, NO MERGE/NO DEPLOY**. This is an offline synthetic *negative* security acceptance oracle. It is **not** a production check, release/CI attestation, target permission or a grant.

## Finding

A reviewer accepting a 40-character immutable commit SHA but relying on ordinary local Git object reads can be misled by repository-local **`refs/replace/<sha>`**. Git transparently presents a different commit's tree, blob and ancestry under the unchanged original SHA; an orphan replacement can also make an originally related commit appear to have no parent. A local replacement ref survives removal of inherited `GIT_*` environment variables, and checking `rev-parse HEAD^{commit}` does not fix it.

**Concrete disposable proof:** a real original commit changes `src/lightup/protected.py`; a separate benign commit based on the same base only adds `tests/test_scope_synthetic.py`. `git replace <original-head-sha> <benign-head-sha>` causes default `git diff <base> <original-head-sha>` to report only the apparently benign file. The exact same diff with `GIT_NO_REPLACE_OBJECTS=1` instead reveals the original production source edit.

This is an **offline Git interpretation ambiguity**, not evidence of an actual exploit against a deployed LightUp instance, and not evidence of malicious activity in any existing worker branch.

## Test-only deliverables

Run locally from a checkout with Git installed:

```sh
python -m unittest discover -s tests -p 'test_scope_git_replace_ref_boundary.py' -v
```

The **nine** genuine disposable-repository tests cover diff spoofing, unchanged SHA / changed tree, original blob recovery, repository-local refs independent of inherited variables, `HEAD^{commit}` pin insufficiency, original history recovery and **false parent ancestry under an unrelated orphan replacement commit**, and two legacy `.git/info/grafts` controls that prove parent history can still be rewritten even when replacements are disabled. Each test uses a temporary directory, does not import production LightUp, opens no network sockets, runs no scans and never alters a real repository.

## Additional optional refusal-only companion

The independent `scripts/check_scope_git_object_identity_preflight.py` now inspects the **local Git checkout** with read-only commands and fixed safe environment. It refuses any local `refs/replace` ref (including packed refs), any legacy `info/grafts` path, an unexpected/nested Git root, missing Git, failed lookups or an inaccessible graft path. It does not delete Git refs/grafts, cannot scan targets, and cannot produce an authorization. Even an apparently clean result is only `REVIEW_ONLY`, never merge/release permission.

```sh
python scripts/check_scope_git_object_identity_preflight.py --repo .
python -m unittest discover -s tests -p 'test_scope_git_object_identity_preflight.py' -v
```

This adds **seven more** disposable Git regression tests, for **16 independent methods** total across both new test modules. The preflight intentionally does **not** import or modify the actively owned #1313 checker. It is a conservative negative-only reusable reference, and does not prevent a local malicious actor changing Git state between checks (TOCTOU). A fully trusted commit attestation requires additional source-owner review, pinning and runtime controls.

## Owner handoff — not an independent fix

- The active source-owner [draft #1313](https://github.com/Zennay/Lightup/pull/1313) must decide whether to set `GIT_NO_REPLACE_OBJECTS=1` **for every Git subprocess**, including `diff`, `rev-list`, `cat-file`, `ls-tree`, `status` and `rev-parse`. Prefer enforcing this centrally in the owner's sanitized Git environment rather than only individual callers.
- **Important independent boundary:** modern Git in the local fixture still honors the deprecated repository-local `.git/info/grafts` file even with `GIT_NO_REPLACE_OBJECTS=1`. For stringent history verification, separately detect and refuse legacy grafts through the repository's actual git-dir and consider verification of raw commit parent object bytes. Never claim that disabling replace refs alone makes commit ancestry immutable.
- Consider rejecting any detected local replacement refs in stricter review mode, but do not infer that absence of a checked ref is a trusted release proof. Exact current-head pinning, clean-worktree checks and Git env sanitization remain independent controls.
- Review the end-to-end local trust boundary, Git configuration, ref/object provenance and TOCTOU separately; this synthetic reference alone does not prove all possible Git integrity issues are resolved.
- Require source-owner review, exact immutable new-branch Python3.11/3.14 hosted unit and real-producer jobs, separately registered permanent VPS execution evidence, independent security/privacy approval and explicit human release decision. **This branch cannot merge or deploy automatically.**

## Collision boundary

This isolated PR adds only two new test paths (`tests/test_scope_git_replace_ref_boundary.py` and `tests/test_scope_git_object_identity_preflight.py`), the opt-in `scripts/check_scope_git_object_identity_preflight.py`, and `docs/scope-git-replace-ref-boundary.md` on a dedicated branch off untouched `main`. It does **not** edit #1313's checker/docs/tests, another worker's files, CI workflows, production authorization, VPS runners, targets, grants or evidence-remediation.
