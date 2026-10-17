# Scope #1541 — Git path identity fail-closed handoff (draft #1538)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Owner-isolated test
addition based on #1538 original exact head
`3eee4f69c28f4192ba1224431f609cb2fb18ebc2`. This branch does
not edit `src/lightup/git_changes.py`, any production authorization/runner
file, or the `claude/lightup-leap` source-owner branch. No release or scan.

## Original-source problem (confirmed in disposable Git repositories)

- `git diff --numstat -M` (without `-z`) applies Git C quoting to
  unusual path bytes when `core.quotePath=true` (the default). A
  UTF-8 filename `café.py` appears in numstat as the text
  `"caf\\303\\251.py"`, while the next `--name-status -z` call
  returns the actual UTF-8 bytes for `café.py`.
- The adapter decodes both outputs with `errors="replace"` and uses
  `numstat.get(path, (None, None))`. The mismatch makes the changed
  source record have missing line counts and `patch=None`, so the
  downstream inferred security review never evaluates that modified
  source line. Tab-containing paths are affected too.
- Distinct byte names `b"\\xfe.py"` and `b"\\xff.py"` collapse
  to the exact same replacement-decoded name `�.py`, which violates
  review change-object identity. This is an audit/coverage defect,
  **not** evidence of a grant or authorization bypass.

## Owner-safe repair contract

1. Parse bounded, zero-delimited, **raw byte** Git numstat and name-status
   output (e.g. `--numstat -z` and `--name-status -z`). Never mix
   C-quoted textual and raw-path representations or decode using
   `errors="replace"`.
2. Decode each full raw path as strict UTF-8, reject undecodable paths,
   duplicate/casefold-ambiguous output, malformed lengths, rename
   ambiguity or missing numstat identity with a generic
   `GitChangeError` / fail-closed HOLD before any inferred verdict.
3. Keep exact-match association for all supported renamed/copied records.
   Bound total Git-output bytes, file count, and patch sizes, and disable
   external diff/textconv/filter execution wherever relevant. Never
   print untrusted raw paths/secrets in error receipts.
4. Make source-owner tests **ordinary passing assertions** after the
   corrective patch; until then, keep the original acceptance cases
   intentionally marked expected RED, separate from the 3 ordinary
   passing controls. Never present `OK (expected failures=3)` as
   a green production-source implementation.

## Reproduction (local temporary Git fixtures only)

```shell
python3 -I -S -B -m unittest discover -s tests \
  -p 'test_scope_git_path_identity_1541_20261017.py' -v
```

First exact pushed SHA `273d225cf1f484a3ff2efb8e1ea79c689730cd0e`.
Connected zSSH `vps-bb300bba`, separate clean throwaway Git clone,
Python 3.14.4: **6 tests = 3 ordinary PASS + 3 intentional source
expectedFailures, zero unanticipated errors**, no tracked modifications.
The known REDs are (a) Unicode filename drops the patch, (b) tab filename
drops the patch, (c) raw byte invalid UTF-8 aliases are not rejected.

## Release boundary

Not consent, a scope grant, a security finding, or trusted GitHub
provenance. No source-owner code edit, merge, deployment, active target,
scanning, handler, grant, or release. Original owner repairs, complete
approved-SHA hosted + permanent named VPS runner CI, separate
authenticated client/operator approval with revocation at use,
independent privacy/security review, and explicit HUMAN GO remain required.
