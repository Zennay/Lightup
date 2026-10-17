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


## W2–W3: independent byte-exact repairability oracle (2026-10-17)

New wholly owned, **unwired**, stdlib-only helper:
[`scripts/scope_git_path_identity_oracle_1541.py`](../scripts/scope_git_path_identity_oracle_1541.py).
It accepts *already collected* native Git `--name-status -z` and
`--numstat -z` byte streams, validates exact UTF-8 identities, changed
path/status/count matching and rename source/target association, and refuses
malformed/oversized/duplicate/casefold/normalization/path-traversal identity
claims with generic `PathIdentityHold`. It never runs Git or opens a
network/file/target, and its returned frozen path tuples convey no consent,
grant, scan, handler permission, trusted Git provenance or release verdict.

Companion [oracle test suite](../tests/test_scope_git_path_identity_oracle_1541_20261017.py)
includes **19 test methods** (including two actual self-contained disposable
Git repositories confirming native `-z` Unicode/TAB bytes and fail-closed
invalid UTF-8) with dozens of adversarial subcases. A separate original-source
witness meta-test refuses hidden TypeError/ImportError/other non-assertion
failures among the three deliberately open source REDs.

**Actual connected zSSH Python3.14.4 at exact pushed
`3170c14e1d5e2d7381ae6a4a0fa4f04220b4f772`: 28 test methods,
25 ordinary PASS + 3 explicitly unresolved original-source
expectedFailures, no unexpected failures/errors; disposable clone worktree
clean.** This is NOT original source-owner patch acceptance, complete project
CI, canonical permanent VPS runner CI, or release proof.

GitHub compare against untouched owner base
`3eee4f69c28f4192ba1224431f609cb2fb18ebc2`: **nine isolated commits,
exactly four wholly NEW files**, no original/parallel worker file changed,
zero behind. [Draft PR #1542](https://github.com/Zennay/Lightup/pull/1542)
targets the feature owner's `claude/lightup-leap` branch (not `main`) to
keep the review focused on these additive changes. Owner still needs a real
strict-bytes, bounded Git adapter repair and all three RED source expectations
upgraded to ordinary PASS before integration.

**HOLD persists. No default-branch merge/deploy, live targets, active scans,
real consents, grants, handlers, or release.**


## W5 · bronhouderfix ontvangen, drie originele REDs opgeheven en volledige compositie · 17-10-2026

De oorspronkelijke eigenaar van [draft #1538](https://github.com/Zennay/Lightup/pull/1538)
heeft op **zijn eigen branch**, onveranderd onder ons eigenaarschap, SHA
`26dd88d33c8735658ae819c7e017b2f36493a039` gepusht met
`--numstat -z` raw-byte, strict UTF-8 en expliciete numstat/name-status
consistentiecontrole. In een **tijdelijke aparte checkout** waren de drie
voorheen expected-RED acceptaties ineens **UNEXPECTED SUCCESS**: daadwerkelijk
alle drie oorspronkelijke defecten in deze fixtures verholpen.

Daarna heb ik uitsluitend op de eigen werkbranch:
- alle drie de oorspronkelijke regressies omgezet naar **gewone strikte PASS**,
  met metatest die geen gemaskeerde expectedFailures toestaat;
- via GitHub Git Data een non-force tweeouder-mergecommit gemaakt
  `d79854d5837f9b75cbb2691d60a4804bc1c20e77`, met alleen exact
  twee byte-identieke upstream bronhouderblobs overgenomen, **zonder die
  externe branch of originele productiebestanden autonoom te bewerken**;
- de echte source-ownervergelijking gehouden op **uitsluitend vier volledig
  nieuwe eigen bestanden** (zero behind, geen externe bestanden in PR-diff).

**Exact nieuwe HEAD via de toegestane verbonden zSSH Python3.14.4**
in eigen schone geheel tijdelijke checkout:
- 28 eigen Git-name identity source-/oracle-tests **28/28 gewone PASS**;
- 26 oorspronkelijke `test_change_review.py` **26/26 gewone PASS**;
- 4 oorspronkelijke `test_change_review_store.py` **4/4 gewone PASS**.
**Samen 58/58 normaal PASS, 0 expectedFailure/FAIL/ERROR.**

**Echte volledige oorspronkelijke suite op exacte eigen HEAD** via zSSH en
normale projectimports, Python3.14.4: **1.301 tests, 2 gewone FAIL** in
uitsluitend reeds afzonderlijk bezeten #1535
`render_scope_registry_history_offline.py` native-I/O warning cases;
de nieuwe Git-scope-integriteitsfix zelf veroorzaakte geen nieuwe unitfailures.
Deze eigen HEAD is **dus niet full-project groen**.

Vervolgens uitsluitend lokaal, **niet gepusht of gemerged**, exact de
ongewijzigde andere bronhouderfix uit
[draft #1536](https://github.com/Zennay/Lightup/pull/1536)
SHA `f8b91596d48f318cb75050b70ccbf5a50d2cd106`
(`src/lightup/capability_registry_history_report.py`, de 2 Python
SyntaxWarning-escapeplaatsen) in een disposable kopie opgenomen:
**1.301 originele tests volledig OK, 0 FAIL/ERROR** op Python3.14.4,
werkelijk getest via zSSH. Dat is een **composiet lokaal bewijs**, geen
gepubliceerde gecombineerde release-commit, definitieve CI, officiële
runner of gebruikersautorisatie.

**DRAFT/HOLD — geen merge naar main, deployment, live scan, grant,
handlerdispatch of release.** Voor echte GO blijven exacte release SHA
complete hosted CI plus benoemde permanente VPS GitHub Actions,
onafhankelijke privacy-/securityreview, authentieke gescheiden client- en
operatorconsent met at-use intrekking, en expliciete menselijke GO vereist.


## W6–W7 · hierarchical path aliases, Unicode display traps and Git metadata semantics (2026-10-17)

**Own branch only; NO source-owner or default-branch edits.** New entirely
owned fixture `tests/test_scope_git_path_hierarchy_1541_20261017.py`
reproduced **eight initially failing methods** (11 methods total) on the
real connected zSSH VPS Python 3.14.4 at SHA `ee0a5b1`. Conservative
repairs to the already owned, *unwired* oracle in `719d7da` then made
all eleven pass. Files that are also claimed as an ancestor directory
(e.g. `a` and `a/b`) and cross-platform case/NFC aliases of ancestor
directories now yield generic `HOLD`, as do invisible Unicode format
characters. This intentionally holds some legitimate Git file-to-directory
transitions; humans must review such cases without treating the return as
authorization.

Next, additional actual red probes initially found **14 failing subcases**
in status/count and Unicode display integrity; malformed Git binary
numstat half-sentinels, noncanonical rename scores, impossible
added/deleted line counts and invisible Unicode whitespace/variation marks
now return `HOLD`. Real ordinary cases (canonical added/removed files,
two-sentinel binary changes, UTF-8/TAB names and sibling source files) still
pass. **No real asset, network probe, Git metadata read or handler is invoked
by the oracle.** Strict lower-level review is only for synthetic/
independently authenticated, already collected byte streams, never
actual repository authenticity.

At exact own HEAD `c9e686184d44aa14b2d8491855705fdf3fd99747`
verified via allowed zSSH, own **17 hierarchy + 21 byte parser + 7
source acceptance = 45/45 ordinary PASS**. Original owner change-review
**26/26 PASS**, original change-review storage **4/4 PASS**:
**75/75 tested, 0 expectedFailures, 0 errors, clean tree.**
Owner-branch comparison: **18 commits ahead/0 behind, exactly five
wholly NEW own paths, no modified existing source, action, runner or
parallel-worker paths**. No GitHub hosted or permanently registered VPS
Actions green is claimed from this local run.

**Still INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** All authenticated
real-world client and operator approvals with at-use revocation,
independent privacy/security review, exact approved release SHA full hosted
and named permanent VPS CI, source-owner integration and explicit HUMAN GO
remain mandatory. NO main merge, deploy, real target, scan, grant,
handler dispatch or release.
