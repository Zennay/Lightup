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


## W8 · whole 1,318-test owner-fix composition on a disposable VPS checkout (2026-10-17)

The **unaltered own** SHA `92d26bee8dfdb4bda6b841ab0e92a05ca942b836`
ran the whole native Python3.14.4 unit suite on the connected zSSH VPS:
**1,318 tests with exactly two existing #1535 native registry-history I/O
tripwire failures (exit 92)**; all new own source/advisory tests passed.
There is **no published full-suite GREEN** at this SHA.

Using a **separate /tmp disposable clone** (NOT a GitHub branch update),
fetched original independent source-owner [draft #1536](https://github.com/Zennay/Lightup/pull/1536)
exact SHA `f8b91596d48f318cb75050b70ccbf5a50d2cd106`,
applied only that already-reviewed owner source blob
`src/lightup/capability_registry_history_report.py` to the disposable
worktree, then actually ran:

```shell
PYTHONPATH=src:tests python3 -B -m unittest discover -s tests -q
```

**1,318/1,318 unit tests OK** (Python 3.14.4, connected zSSH); exact
checked-out own commit remained `92d26bee`, with **exactly one local
uncommitted source-file modification** in the disposable checkout.
No original owner branch, own GitHub branch, main, runner, deployment,
real target, authorization, grant, scan or handler was modified.
Expected test-only warning output (Python3.14 invalid escapes in separate
original assertion fixtures, ResourceWarnings and local TLS BrokenPipe)
is not a failing unittest status. This proves local composability,
**not** an approved integrated release SHA or registered VPS Actions job.

Production release remains **DRAFT/HOLD** pending source-owner integration,
permanent named runner exact approved-SHA CI, full hosted CI, separate
authenticated client/operator permission including revocation at use,
independent privacy/security and explicit HUMAN GO. Neither test
success nor this offline reviewer grants consent or execution rights.


## W10 · Synthetic-only executable Git byte-stream HOLD preflight (2026-10-17)

Additional independently owned, **new** files:
- `tests/test_scope_git_path_stream_coherence_1541_20261017.py`: actual RED acceptance pinned byte-exact ordered row identity, Windows-like trailing period/space, and hidden C1 Unicode control characters. Initial actual connected zSSH execution: **12 failed subcases**. Our *already owned, unwired* oracle was corrected by `a82ce06`, after which all 12 ordinary methods passed and the existing 45 own tests remained green.
- `scripts/review_scope_git_path_streams_synthetic_1541.py`: executable bounded stdin-only synthetic review, **not imported or wired by LightUp production**. It reads one `lightup.scope_git_paths_synthetic.v1` exact-canonical sorted/minimal JSON document, requiring `synthetic_only:true` and exact `status_b64`/`numstat_b64` raw Git zero-delimited byte-stream fields. It limits the JSON to 786432 bytes and each decoded field to 262144 bytes. Invalid schema, duplicate keys, unknown authority-like fields, noncanonical JSON/base64, stream mismatches, malformed Unicode or size => **generic `HOLD` / exit 2**. Valid synthetic canonical shapes => **`REVIEW_ONLY` / exit 3**. Exit 0 is impossible by design. Both fixed JSON receipts contain seven *literal false* authorization/consent/permit/dispatch/execution/merge/release fields and no filenames, raw user bytes or secrets.
- `tests/test_scope_git_path_stream_cli_1541_20261017.py`: 14 ordinary executable subprocess/purity tests, including Python `-I -S -B` isolation, size/Unicode/dedup/privacy/error-path fences, direct `open`/socket/subprocess I/O tripwires in the pure reviewer.
- `tests/test_scope_git_path_native_cli_1541_20261017.py`: **5 ordinary actual local Git -z integration tests**: UTF-8/TAB multi-file order and rename accepted as fictional advisory; literal file-to-directory transition, invalid UTF-8 and terminal-dot names produce HOLD. Local fixture repositories have disabled Git hooks, no remotes, no credentials and no target contact.

To run a prebuilt *fictional* canonical packet:

```sh
python3 -I -S -B scripts/review_scope_git_path_streams_synthetic_1541.py < synthetic-packet.json
# return 3 = REVIEW_ONLY; return 2 = HOLD; never return 0
```

**This is not a GitHub provenance validator.** A canonical JSON snapshot is
still self-asserted unless independently authenticated. A REVIEW_ONLY receipt
cannot grant client/operator consent, authorization, scans, handlers, releases
or production CI GO. None of the code is wired into production, GitHub Actions,
real Git repositories, scans, grants or dispatchers. Original #1538 owner
branch and separate #1536 source-owner fix remain untouched. No CI runner
queues added. **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**


## W11 · Cold Python 3.14 verification; cached bytecode is not CI proof (2026-10-17)

At code-and-doc head `2f24d8f1d4526fcfc20f30d9181056e62f184049`,
the isolated connected zSSH Python3.14.4 VPS test selection completed:
**76/76 own scope Git path tests, 30/30 original change-review/
review-store tests and 86/86 original producer integrations PASS**
(**192 ordinary tests**, clean own checkout).

A subsequent **warm checkout** `PYTHONPATH=src:tests python3 -B -m
unittest discover -s tests -q` reported **1,349 tests OK**. This
status was **NOT a valid cold native-warning proof**: compiled
`__pycache__` modules can be read even with `-B` (which prevents
new cache writes, but does not by itself disable cache reads). A
separate explicit source `compile(...)` under
`warnings.simplefilter('error', SyntaxWarning)` proved the original
`src/lightup/capability_registry_history_report.py` still has
invalid escaped-backtick source.

To eliminate stale cache effects, I created a **new source-only /tmp
Git checkout** at *exact own SHA* `2f24d8f` (not a dirty copy) and
ran native fleet acceptance and the **entire** Python3.14 suite
without any pre-existing bytecode. Exact results:

- Original native fleet: **3 methods, two ordinary FAIL**, both the
  already owned #1535 warning-triggered exit 92 from
  `render_scope_registry_history_offline.py`.
- Cold full suite: **1,349 tests, exactly those two ordinary FAIL**
  (zero new own Git-path/CLI failures), exit 1; tree clean.
- Independently **new, separate /tmp checkout** on the *same exact
  own commit* plus **only the already-reviewed independent #1536
  owner-fix source blob** from
  `f8b91596d48f318cb75050b70ccbf5a50d2cd106`:
  explicit compile with syntax warnings as errors **PASS**, cold
  complete Python3.14 suite **1,349 tests OK**, exit 0.
  The only checkout difference is an uncommitted
  `M src/lightup/capability_registry_history_report.py` in the
  *disposable proof copy*, never pushed or merged.

This corrects any misleading earlier **warm green** status:
the *published* own branch **is not cold-full-green** without the
separately owned source correction; the clean combined fixture is
green but **NOT** an integrated, published, reviewed release SHA or
named permanent GitHub VPS Actions job. The owner #1536 controls that
source fix; this lane has NOT changed the owner source or branch.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No main merge,
deployment, active target, scans, grants, handlers or release.
Independently authenticated separate client/operator consent with
at-use revocation, security/privacy review, exact final release-SHA
full hosted and permanently registered VPS GitHub Actions and explicit
HUMAN GO remain necessary.


## W12 · Generic HOLD on partial CLI receipt output (2026-10-17)

Another entirely NEW own test module
`tests/test_scope_git_path_stream_io_1541_20261017.py`
uses injected, purely local fake stdin/stdout objects (no filesystem,
network, Git command, real handler or source-authorization import).
The initial real allowed zSSH Python3.14.4 run found **5 genuine failing
cases** in our new offline synthetic stdin CLI: a short write,
overreported count, and `True`, `None`, or zero-returning stdout
acknowledgements could let `main()` still exit **3/REVIEW_ONLY** despite
an incomplete/unverifiable output receipt.

The independently owned CLI is now hardened in commit
`f3571d8b11a8bd4585ccf1dd582150d686c5f05a`: only an **exact
built-in integer** acknowledgement equal to the **entire fixed receipt
byte length**, followed by a successful flush, can preserve the
synthetic-only exit 3. Any malformed, short or exceptional stdout
transport yields **HOLD exit2**, never an approval. This cannot recover
a partially transmitted message, so consumers must validate both
**complete fixed JSON and exact exit code**; even REVIEW_ONLY conveys
zero authorization in any event. The same suite proves stdin read
exceptions and extra CLI arguments yield fixed generic HOLD without
echoing synthetic secrets. A valid subsequent or preceding request
never inherits a previous review status.

Actual connected zSSH isolated checkout SHA `f3571d8`:
**8/8 new transport tests GREEN** (5 previously RED cases repaired)
and **84/84 own Git path/test/CLI tests GREEN**, clean Git tree.
No source owner, existing workflow, external worker, main branch,
scan, grant, handler, target or deployment was changed.
The previously recorded **cold** Python3.14 complete project test
evidence at earlier code SHA `2f24d8f` remains precise: cold original
1,349 had 2 independently owned #1535 FAIL; independent disposable
composition with the #1536 fix was 1,349 OK. Do **not** substitute that
old SHA evidence for a full current-HEAD release CI.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Full exact
approved release SHA hosted and permanently registered named VPS
Actions, independently authenticated separate client/operator
consent with at-use revocation, security/privacy and explicit
human GO remain outstanding.


## W14 · Final *current code* SHA fresh-checkout full 1,357 test composition (2026-10-17)

Previous W11 full test numbers were at an earlier code SHA; after
adding the 8 stdout transport tests the actual current code SHA
is `bdc0efc87dfac54e8483155f0f3e2425a9ceddcc`.
Two **independently new and clean** /tmp Git clones of this
**exact code SHA** were tested on connected zSSH `vps-bb300bba`
Python3.14.4, each without inherited bytecode cache:

1. Original unchanged own Git HEAD: **1,357 unit tests, exactly
   TWO ordinary FAILS** from already-known independently owned #1535
   native registry-history SyntaxWarning `exit 92`, and no other
   failure. Git checkout was clean, original owner source unchanged.
2. Another fresh disposable clone, **same exact own HEAD**, with
   **only** independent #1536 owner SHA
   `f8b91596d48f318cb75050b70ccbf5a50d2cd106`'s already
   fixed source blob
   `src/lightup/capability_registry_history_report.py` copied
   locally **without commit or push**: strict warning-as-error
   source compile **PASS**, whole Python3.14.4 unit suite
   **1,357/1,357 ordinary PASS**, exit0, **exactly one local
   dirty source path** in the *disposable* test tree.

In addition, the last own exact head remains **200/200 targeted
and original integration tests GREEN** (84 own Git path incl. CLI,
30 original review/store and 86 producer integrations) in an
independent clean checkout.

**Do not confuse this with approved release CI**: full hosted
and permanently registered named GitHub Actions VPS jobs on the
final proposed **integrated release SHA** have not completed;
current owner source still needs independent branch integration,
real authenticated separate client/operator consent and at-use
revocation, privacy/security review and explicit HUMAN GO.
Own GH branch/source owners/main/services were **never modified**
by the local composite. **INCUBATE M3/M7 · PLAN/LAB ONLY ·
DRAFT/HOLD; NO MERGE, DEPLOY, SCAN, GRANT, DISPATCH OR RELEASE.**
