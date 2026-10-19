# LightUp · Original Authorization Casebook HISTORY

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This is an add-only HUMAN review product on immutable original Casebook source owner [PR #1620](https://github.com/Zennay/Lightup/pull/1620), pinned to `fa3a260234daa1178b5f6e4fc95cbd36e12d61fd`. No original Python source, account/login, approval, grant, risk, activation, scanner, target, CI/QA, or workflow paths are changed.

## Why it exists

The original [Authorization Casebook](../docs/authorization-casebook-20261018.md) authenticates a real account against LightUp's original persisted DomainStore, hard-selects an authorized tenant and creates one private, non-authorizing human review snapshot. Its browser supports one earlier/current comparison only. For substantial scope operations, a human also needs a **complete, offline, 2–12 snapshot progression** with exact original request, engagement, grant and risk-decision source identity changes, case/risk H O L D counts and an offline scriptless visual desk.

This companion does **not** claim to authenticate the bytes of downloaded source packets; a login at producer time is not a transferable signature. All content may be altered after original export. It does not issue authorization or convert copied source data into independent consent, revocation evidence or a verified grant.

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

The operator-selected **ordinal** order is not independently verified calendar chronology. CLI exits **2** on `REVIEW_ONLY` and **3** on `HOLD`, never exit 0 as an approval. Run only on a trusted Linux environment with original inputs in 0700 parent directory and original files 0600. Source admission is whole-batch and fail-closed before any output is created. Existing destination refuses overwrite; outputs are placed into a newly created 0700 directory with exclusively created 0600 files.

## Complete product outputs

The one new PRIVATE folder contains:

- `index.html`: responsive **scriptless** offline private browser report with exact per-original-ID appearing/absent/field-changed review, source HOLD trend, original declared counts. Names/identifiers may be sensitive.
- `anonymous.html`: separately scriptless local HTML briefing excluding all original source IDs, client, request/grant/risk identities and source timestamps. Aggregate appearance counts may remain privacy-sensitive.
- `anonymous-counts.json`: exact ordinal counts and between-ordinal change quantities only; literal authority flags are all false.
- `anonymous-counts.csv`: separate source-free count series for human spreadsheet viewing.
- `private-source-changes.csv`: original record IDs and changed field names in private report only; CSV formula-spoofing is escaped.
- `human-followup.txt`: original counts and human follow-up questions; contains no raw evidence, customer names, passwords, hostnames, grant references or source record IDs.
- `private-source-inventory.json`: exact original-input byte length and SHA-256 by private ordinal, **unsigned/untrusted** and excluded entirely from anonymous handoffs.
- `private-human-case-queue.csv`: all original engagement IDs from the selected packet series, the most recently **declared** HUMAN next action, recorded status, first-party original attention category, number of snapshot appearances and attention transitions. The accompanying private HTML displays the same ranked queue. This ranking describes HUMAN source reconciliation workload, **not** verified security risk or real authorization priority.

The browser is HTML+CSS only: strict default-deny CSP with one pinned local style hash, no script, network, forms, external resources or dependency. Source record values are escaped as text. All original identity matching is exact within the same selected original tenant; a cross-tenant imported file refuses the **entire batch**. Duplicate JSON keys, altered source structure, unknown authority, invalid count consistency, duplicate IDs, non-regular/symlink files and unsafe directory permissions are rejected.

**Classification is strictly observational:** Missing grant ≠ revocation, approved request record ≠ separate present client/operator consent, same source row ≠ durable live authorization, fewer HOLD categories ≠ safer system, no difference ≠ PASS. Never use to authorize active targets. A reviewer must return to the **original current authenticated domain state** with all original scope/approval/revocation and independent client/operator permission checks.

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
