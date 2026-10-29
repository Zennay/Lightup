# LightUp · Original Authorization Casebook HISTORY

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is an add-only HUMAN review product on immutable original Casebook source owner [PR #1620](https://github.com/Zennay/Lightup/pull/1620), pinned to `fa3a260234daa1178b5f6e4fc95cbd36e12d61fd`. No original Python source, account/login, approval, grant, risk, activation, scanner, target, CI/QA, or workflow paths are changed.

## Why it exists

The original [Authorization Casebook](../docs/authorization-casebook-20261018.md) authenticates a real account against LightUp's original persisted DomainStore, hard-selects an authorized tenant and creates one private, non-authorizing human review snapshot. Its browser supports one earlier/current comparison only. For substantial scope operations, a human also needs a **complete, offline, 2–12 snapshot progression** with exact original request, engagement, grant and risk-decision source identity changes, case/risk H O L D counts and an offline scriptless visual desk.

This companion does **not** claim to authenticate the bytes of downloaded source packets; a login at producer time is not a transferable signature. All content may be altered after original export. It does not issue authorization or convert copied source data into independent consent, revocation evidence or a verified grant.

## One-command original-account capture with automatic HISTORY

The new `capture.py` eliminates the manual export-and-reopen choreography while **reusing the original owner-maintained** `lightup.auth_casebook.authenticated_casebook` and its original `_write_private_json`. It prompts securely for an **original** operator/client password with `getpass`, respects original lockout/current persisted role and tenant selection, checks all pre-existing packets first, then writes exactly one original-source 0600 `casebook-NN.json`. It cannot change a grant, issue approval, touch a target, elevate risk or bypass an original revocation decision. **The original authentication routine may update its existing login/lockout counters.** The companion creates no login, session, token, authentication cache or authorization privilege.

Initialize your own trusted PRIVATE (0700) folder through your normal approved local file-management workflow. Do not weaken directory permissions to accommodate LightUp.

On the first original capture (one snapshot; no comparison yet):

```bash
PYTHONPATH=src python scope-casebook-history/capture.py \
  --database /private/original-lightup.sqlite \
  --email actual-operator@example.invalid \
  --client ORIGINAL_TENANT_ID \
  --packet-dir /private/casebook-originals
```

On each later authenticated original capture, also publish a **new** history in a separately private output parent:

```bash
PYTHONPATH=src python scope-casebook-history/capture.py \
  --database /private/original-lightup.sqlite \
  --email actual-operator@example.invalid \
  --client ORIGINAL_TENANT_ID \
  --packet-dir /private/casebook-originals \
  --history-output-dir /private/human-reviews/new-history-02
```

Use a fresh `new-history-03`, etc., for subsequent moments; no overwrite or automatic deletion. The original producer's published `casebook-NN.json` remains preserved **even if a later HUMAN history export fails**. If that happens, investigate the single cause without weakening permissions and use `history.py --packet-dir /private/casebook-originals --output-dir /private/human-reviews/NEW` to resume without calling login a second time. The tool never silently overwrites or removes previous private snapshots.

These are *operator-selected ordinals*, not independently witnessed times. The output contains unsigned local original source data; only a fresh original authenticated read under current separately verified client/operator consent and action-time revocation can inform an actual authorization decision elsewhere.

## Original source workflow

First use the original owner command on its held branch, in a trusted private operator environment, to produce each **0600 original Casebook v1 JSON**. See [the original operating guide](../docs/authorization-casebook-20261018.md). Authenticated login is performed by the **original** program, not this companion; no password or credential is requested or handled here.

Create a new destination under owner-private directories, never the original file location:

```bash
umask 077
mkdir -m 700 /private/lightup-reviews
PYTHONPATH=src python scope-casebook-history/history.py \
  --input /private/original-casebook-moment-01.json \
  --input /private/original-casebook-moment-02.json \
  --input /private/original-casebook-moment-03.json \
  --output-dir /private/lightup-reviews/new-human-history
```

**Alternative exact-folder bulk intake:** when handling a complete owner-private original export batch, place only the consecutive source files `casebook-01.json` through `casebook-NN.json` (2–12, 0600 each) into a private 0700 folder, then use `--packet-dir /private/original-casebooks` **instead of** repeated `--input`. Any unknown file, gap, symlink, insufficient privacy permissions or extra hidden member makes the whole selection HOLD. The same exact `--packet-dir` mode works on `reopen.py` with `--history-dir`.

The operator-selected **ordinal** order is not independently verified calendar chronology. CLI exits **2** on `REVIEW_ONLY` and **3** on `HOLD`, never exit 0 as an approval. Run only on a trusted Linux environment with original inputs in 0700 parent directory and original files 0600. Source admission is whole-batch and fail-closed before any output is created. Existing destination refuses overwrite; outputs are placed into a newly created 0700 directory with exclusively created 0600 files.

## Complete product outputs

The one new PRIVATE folder contains:

- `workroom.html`: separately generated, CSP-pinned, one-file local interactive HUMAN review workroom with strict original-source-locked private CSV resume/export.
- `workroom-current-template.csv`: exact current original packet-only human review template; original historical template remains separately available.
- `index.html`: responsive **scriptless** offline private browser report with exact per-original-ID appearing/absent/field-changed review, source HOLD trend, original declared counts. Names/identifiers may be sensitive.
- `anonymous.html`: separately scriptless local HTML briefing excluding all original source IDs, client, request/grant/risk identities and source timestamps. Aggregate appearance counts may remain privacy-sensitive.
- `anonymous-counts.json`: exact ordinal counts and between-ordinal change quantities only; literal authority flags are all false.
- `anonymous-counts.csv`: separate source-free count series for human spreadsheet viewing.
- `private-source-changes.csv`: original record IDs and changed field names in private report only; CSV formula-spoofing is escaped.
- `human-followup.txt`: original counts and human follow-up questions; contains no raw evidence, customer names, passwords, hostnames, grant references or source record IDs.
- `private-source-inventory.json`: exact original-input byte length and SHA-256 by private ordinal, **unsigned/untrusted** and excluded entirely from anonymous handoffs.
- `private-human-case-queue.csv`: all original engagement IDs from the selected packet series, the most recently **declared** HUMAN next action, recorded status, first-party original attention category, number of snapshot appearances and attention transitions. The accompanying private HTML displays the same ranked queue. This ranking describes HUMAN source reconciliation workload, **not** verified security risk or real authorization priority.
- `private-human-review-template.csv`: editable original-ID-private HUMAN collaboration sheet with source columns pinned and human-only stage/route/blocker choices; it does not automatically submit or change grants.
- `private-human-case-transitions.csv`: exact per-original-engagement recorded HUMAN action/attention changes between adjacent reviewer-selected snapshots; never a verified revocation.
- `private-original-case-details.csv`: original source-linked engagement/grant/risk dossier rows without raw assets, credentials, notes or evidence.
- `anonymous-source-order.csv`: ordinal-only comparisons of unsigned source-declared timestamps with explicit HOLD labels, not an authenticated timeline.
- `anonymous-human-actions.csv`: latest original HUMAN action category counts only; potentially sensitive small-cell aggregates.

The browser is HTML+CSS only: strict default-deny CSP with one pinned local style hash, no script, network, forms, external resources or dependency. Source record values are escaped as text. All original identity matching is exact within the same selected original tenant; a cross-tenant imported file refuses the **entire batch**. Duplicate JSON keys, altered source structure, unknown authority, invalid count consistency, duplicate IDs, non-regular/symlink files and unsafe directory permissions are rejected.

**Classification is strictly observational:** Missing grant ≠ revocation, approved request record ≠ separate present client/operator consent, same source row ≠ durable live authorization, fewer HOLD categories ≠ safer system, no difference ≠ PASS. Never use to authorize active targets. A reviewer must return to the **original current authenticated domain state** with all original scope/approval/revocation and independent client/operator permission checks.

## Interactive one-file PRIVATE HUMAN Casebook Workroom

New generated `workroom.html` is ready to open as a **single local HTML file**. The PRIVATE original `index.html` links to it. It presents exactly the **last selected original Casebook snapshot** (not old absent records) in a responsive, filterable HUMAN review workspace:

- Search the original engagement ID, original request-linked action, or original HOLD label; filter by current human stage or whether the original source attention was HOLD.
- Expand the PRIVATE original per-case dossier in the SAME local table to read original source grant and risk record IDs, the recorded request-binding and grant-window HOLD labels and original source-next-actions. Values are retrospectively read from the final original Casebook packet, never current authority. Raw targets/evidence/credentials are never inserted.
- Update three HUMAN-only dropdown fields per original case: `human_stage`, `human_followup_route`, `human_blocker`. Original engagement ID, source next action, source attention and source status remain **read-only** and are not changed in the original database.
- Live in-tab HUMAN workload counts (under investigation, awaiting owner, documented and blockers) and a bounded local `Export PRIVATE HUMAN CSV` action; that CSV uses the exact same columns and row order as **`workroom-current-template.csv`**, which includes ONLY engagements from the LAST original packet. The broader `private-human-review-template.csv` retains historical/absent records and must not be used to restore this current-packet workroom.
- Choose a previously exported PRIVATE HUMAN CSV and use **Restore**. Before changing any dropdown, the local app requires exact case count, matching original IDs, immutable original action/HOLD values in the original order, strict header and column counts, valid enumerated stage/route/blocker options, bounded file size and explicit human confirmation. Invalid or cancelled restore preserves all existing dropdowns.
- Confirmed reset affects only the local tab. No localStorage, cookies, indexedDB, credential collection, upload, scanner, target/network connection, external resource, source grant, consent or authorization action.
- An additional ID-free HUMAN workload summary CSV can be exported locally from the tab; it includes only fixed stage, route and blocker category counts. Small-cohort counts may remain sensitive.
- Offline CSP pins both standalone inline JavaScript and CSS to SHA-256. The browser app uses only DOM text/attributes escaped from already admitted original-source declarations; no source data is interpolated into executable JavaScript. The original signed-off source boundaries, role/tenant checks and release requirements are unchanged.

**Important:** This workroom is a PRIVATE local HUMAN editor for already selected source declarations, not an approved source update or evidence of a valid grant. An exported CSV can contain sensitive original engagement IDs. No local HUMAN stage (including `documented`) means a security fix was verified or an assessment may proceed. Current separate authenticated client/operator consent and at-action revocation remain outside this offline product.

## Offline HUMAN follow-up workroom, directly from report

Open the generated private `index.html` locally. Its navigation now links the PRIVATE original engagement queue, original recorded changed fields, human summary and an editable **PRIVATE human follow-up CSV template**. The anonymous `anonymous.html` links only source-free count exports. Everything is local, without scripts, model calls, uploads or live source access.

The editable sheet contains **exact original engagement ID**, unchanged source-declared next action and attention category, followed by three human-only editable fields. Retain the first three columns unchanged. Human reviewers may choose:

- `human_stage`: `unreviewed`, `investigating`, `awaiting-owner`, `documented`.
- `human_followup_route`: `unassigned`, `original-scope-owner`, `client-clarification`, `independent-security-review`, `operator-followup`.
- `human_blocker`: `none`, `missing-source`, `missing-owner`, `needs-independent-consent`, `requires-revocation-review`, `unresolved-tenant-lineage`.

This is a portable, non-authorizing human collaboration sheet. The initial sheet comes from real original source-owner Casebook records; the **human selections are not authenticated**, do not change the original database, and never create/close a genuine risk approval, engagement or authorization grant. Treat the sheet as private: it contains original engagement IDs and original source action labels. The built-in report never treats "documented" as a verified remediation or allows a PASS.

## PRIVATE exact-source reopening

After transfer or operator handoff, reopen the existing history against the **same original source bytes in the same chosen order**:

```bash
PYTHONPATH=src python scope-casebook-history/reopen.py \
  --input /private/original-casebook-moment-01.json \
  --input /private/original-casebook-moment-02.json \
  --input /private/original-casebook-moment-03.json \
  --history-dir /private/lightup-reviews/new-human-history
```

The read-only reopener rejects unknown/extra files, unsafe permissions, modified source JSON bytes, mismatched source ordinal, malformed/duplicated private inventory keys and any changed generated HTML, CSV, JSON or follow-up content. It **recreates the original results in memory** and compares each full output byte sequence. No source input or output is modified by reopen; exit 2 means REVIEW_ONLY data consistency, never a passing security release. SHA-256 is an unsigned local integrity hint and cannot authenticate the originating account, original source truth, permission, consent, legitimate chronology or human go-ahead.

## Mandatory release gate and ownership

This branch is a child of unchanged held original #1620, not a merge into `main`. It owns only new files in `scope-casebook-history/`, and does not take over source-owner #1570/#1614/#1620/#1624/#1641, scope #177/#182/#829 or permanent runner configuration. Existing exact-head hosted AND named permanent VPS CI, original source-owner/security/privacy review, real independently authenticated current client/operator consent with action-time revocation, and explicit HUMAN GO remain mandatory. Do not merge or deploy, create a new grant, activate a target, or run any QA/regression/test suite under this deliverable.

## Privacy-minimized HUMAN action portfolio

The `anonymous.html` workroom now includes a source-only **latest-packet HUMAN next-action workload summary** grouped by the pinned original Casebook's fixed `next_review_action` categories. Companion `anonymous-human-actions.csv` contains category labels and numeric counts only, no engagement, grant, request, risk, tenant or user IDs, timestamps, source hashes, passwords or assets. Small-cell counts may reveal sensitive operating information and should still be reviewed before sharing. No source action category implies independently confirmed approval, urgency, exploitation, remediation, revocation or at-use consent.

## PRIVATE original authorization dossier drilldown

The scriptless local PRIVATE `index.html` now contains an expandable per-engagement review dossier for the **latest explicitly selected original Casebook packet**, reusing source-only recorded engagement, grant and risk fields. It links each original grant row's local opaque ID, recorded original request-binding label, grant-window observation and bound request ID, plus linked original risk record ID, status and recorded HUMAN provenance observation. No raw target assets, actual grant references, user emails, client names, evidence or passwords are included. Foreign-tenant source rows remain excluded by the original Casebook producer. A standalone `private-original-case-details.csv` has these same source-only records, linked directly from private HTML and byte-bound at reopen; it **never appears in anonymous output**.

This is a **retrospective source explanation** to help identify the original owner and resolve #177/#829-style request↔grant/tenant HOLD categories, not a new direct authorization fix. Even a record labelled REQUEST_SCOPE_COMPATIBLE_UNVERIFIED does not prove independent consent or authorize an assessment. Genuine request approval, scope, risk, grant, revocation, actor and at-use permissions remain exclusively with original source-owned domain/execution policy.

## Original source-bound engagement HUMAN attention timeline

The private standalone `index.html` now contains per-identity *source-declared* engagement changes across each adjacent pair of original Casebook snapshots: appeared/absent records, changed original next HUMAN action/attention category and changed original engagement status. The separate `private-human-case-transitions.csv` includes exact original engagement IDs and the before/after original source labels. It is linked from the PRIVATE HTML launchpad and is excluded entirely from anonymous HTML/CSV/JSON. Source absence is not proven revocation, a source status change is not real grant activation, and HUMAN queue changes are never an independently verified security risk or consent. Bounded to 2,400 complete transitions; overflow fails HOLD instead of silently dropping sensitive source changes.

## Original source-stated chronology contradictions

The private and anonymous scriptless HTML reports now expose the selected packet ordinal pairs with `HOLD_DECREASED_SOURCE_TIMESTAMP`, `HOLD_REPEATED_SOURCE_TIMESTAMP`, or `INCREASING_DECLARED_ONLY_UNVERIFIED`. An additional `anonymous-source-order.csv` contains only those ordinal pairs and fixed status labels, no source timestamps or client/engagement IDs. A repeating or decreasing **self-declared** snapshot time raises a visible discussion warning; increasing timestamps are not proof that sources are untampered, consent was live, or authorization existed. The tool never automatically rearranges reviewer-selected packet order or treats a chronology label as GO.

## Bounded complete review semantics

Original inputs are limited to 12 packets × 512 KiB, with at most 200 source records per original family and no more than 3,200 literal changed record appearances across the selected adjacent packet pairs. The browser output contains the **entire** admitted sequence; if that upper bound is exceeded the operation fails closed rather than silently truncating a report. The read-only reopened private artifact size ceiling is 8 MiB per output. Separate small-cell anonymized counts may still be sensitive and are never a green assessment or release.
