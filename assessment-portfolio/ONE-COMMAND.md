# LightUp · One-command Original Human Assessment Workspace

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

### From original human source to a complete offline private workspace

The original owner-private `assessment-archive/archive.py` and `followup.py` already provide archive manifest and source-bound human choices. This new one-command operator entrypoint takes those two existing ORIGINAL files **directly**, instead of asking a human to export an intermediate agenda for each source and later manually package another product.

```sh
python3 assessment-portfolio/one_command.py \
  --original-manifest /private/ORIGINAL-archive-A.json \
  --original-manifest /private/ORIGINAL-archive-B.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --original-choices /private/ORIGINAL-choices-B.json \
  --as-of 2026-10-18 \
  --output /private/NEW-complete-human-workspace.zip
```

Exactly 1–12 original manifest/choices pairs can be supplied in corresponding order. Every source is checked with the **actual unchanged original** manifest validator, human choices validator and agenda renderer, then passed to the independent original-agenda read-only portfolio admission. Manifests may not repeat, and all original private agenda source statuses (including HOLD) remain unchanged.

The complete single owner-private ZIP combines:

1. `index.html` — scriptless full source-bound human workload dashboard.
2. `interactive-capacity-studio.html` — fully local capacity planning, browser-based PRIVATE source-bound capacity saving, restoring and aggregate-only download.
3. `original-human-review-studio.html` — fully local human-only stage/role/date editing, bulk human selection, prior/new diff and source-bound proposal export.
4. `original-private-agenda-01.json`, `original-private-agenda-02.json`, ... — full unchanged original human agenda JSON, exactly linked to the original manifest and choices, ready for separate human return commands.
5. `private-source-bindings.json` plus `private-original-source-map.json` — original SHA-256 byte correlations; owner PRIVATE and unsigned.
6. `aggregate.html`, `aggregate.json`, `aggregate.csv` — anonymous human action counts; review small-group metadata before sharing.
7. `START-HERE.txt` and `ORIGINAL-HUMAN-START-HERE.txt` — precise offline navigation and manual original-schema receive instructions.

The source snapshots are checked before a single fully assembled ZIP is published. Any mismatch, changed choice content, duplicate original manifest or malformed original admission HOLDs the whole operation; **no partial output**. The original exclusive fsynced 0600 publisher never overwrites. All HTML runs from files with no server, network requests, browser storage, remote assets, scanner, model, grants or customer database mutation.

A source hash is only an unsigned local byte correlation. No original raw lab finding/evidence/target file, source manifest, choices draft or customer credential is bundled. The user still needs the original trusted manifest and choices separately to submit human-only changes via [proposal_return.py](REVIEW-RETURN.md). The portable ZIP is PRIVATE and must not be shared as anonymous evidence.

For preparing the **next full private offline review workspace** directly from those proposals, use [review_cycle.py](REVIEW-CYCLE.md). This also returns new original human choices without touching any previous files.

For returning the human proposals from the complete ZIP **without manually extracting the original agendas**, use [workspace_return.py](WORKSPACE-RETURN.md). It independently reconstructs each original agenda and emits a new private original-schema human choices bundle.

The new CLI only composes existing offline source-owner modules; it never initiates lab evaluation, original scan, dispatch, consent, grant, retest or release. Exit 2 for REVIEW_ONLY, 3 for original HOLD/rejected input, never permission. Original exact-head hosted/permanent named VPS CI, source-owner + independent privacy/security reviews, genuine separately authenticated current client/operator consent with at-use revocation and explicit HUMAN GO remain mandatory before release.

The newly generated private ZIP also includes `workspace-home.html` for local navigation and `private-workspace-content-map.json` for locally recorded SHA-256 byte consistency checks of included interface/report members. Both are owner-private and non-authorizing; the map is unsigned. See [CONTENT-INTEGRITY.md](CONTENT-INTEGRITY.md).

## Source-change HOLD before publication

The native one-command original importer now reads the exact original manifest and HUMAN choices a second time **after rendering the full private ZIP** and again immediately before its exclusive owner-private publication. It verifies that every re-opened original SHA-256 equals the original admitted source/choices pair in the ZIP's exact slot-ordered private source map; a changed file yields HOLD and no new published output. The SHA is only local byte correlation, not source authenticity, client consent or permission. This does not turn the result into a trusted security finding or a released assessment.
