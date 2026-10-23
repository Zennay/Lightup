# LightUp · Disjoint Human Proposal Merge

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.** This is a human-only collaboration mechanism for **one original owner-private archive**. It does not authenticate any reviewer, certify remediation, grant permission or enable a security scan.

## Purpose

Several reviewers may independently edit human stages, next neutral roles and proposed review dates for **different original source slots** in the standalone offline [Review Studio](REVIEW-RETURN.md). Their separate PRIVATE JSON proposals must be reconciled without last-write-wins, without changing the old original human source and without mixing client/asset contexts.

The new `merge_proposals.py` accepts 2–12 different **original-bound proposals** for the SAME original manifest, choices and agenda. It accepts only proposals whose changed source-slot sets are disjoint. Two proposals touching the same original slot, even changing different human fields, cause a complete HOLD. This forces a real human owner to resolve the overlap rather than having software silently pick a winner.

```sh
python3 assessment-portfolio/merge_proposals.py \
  --original-manifest /private/ORIGINAL-archive.json \
  --original-choices /private/ORIGINAL-human.json \
  --original-agenda /private/ORIGINAL-agenda.json \
  --proposal /private/REVIEWER-A-human-proposal.json \
  --proposal /private/REVIEWER-B-human-proposal.json \
  --output /private/NEW-owner-private-disjoint-merge.zip
```

All original manifest/choices/agenda bytes are pinned before proposal validation and rechecked after. Each proposal runs through the **unchanged original manifest and human-choice validators**, the strict original agenda checks, and the [single-source original-schema receiver](REVIEW-RETURN.md), so it must match the exact original source digest, source slots, original stages/roles/dates, original status and literal false-only authority flags. Duplicate proposal fields, other extra fields or stale human values are rejected by the original/source-specific readers.

**Output is atomic:** a single **new** fsynced 0600 private ZIP is published only after the entire batch is admitted, with:

- `new-original-human-choices.json`: original valid LightUp `lightup.archive_human_followup.v1` containing only disjoint human edits and all unchanged original source identities/hashes.
- `human-merge-manifest.json`: exact original three-source SHA-256 digests, private source slot contributions per proposal, new output digest and false authority flags.
- `index.html`: scriptless, offline private overview of changed original source slots and the contributing reviewer proposal numbers (not authenticated identities).
- `START-HERE.txt`: human handoff and release limits.

Original client findings, exact targets, evidence files, private credentials and assessment case records are NOT bundled. The output remains PRIVATE because original source-slot hashes are included in the choices JSON and metadata.

Recipient separately selects the unchanged matching original manifest and runs original `assessment-archive/agenda.py` with the extracted new choices JSON. This action produces another **human-only agenda**; it does not modify grants, domain state, scanners, source issue status, client permissions or target evidence.

**Exit semantics:** 2 = all sources for human REVIEW_ONLY; 3 = retained source HOLD or rejected input; never 0 as an authorization result. No QA/test suites are authored or executed. Original exact-head CI, original owner and independent security/privacy review, separately authenticated actual client/operator consent, action-time revocation and explicit HUMAN GO remain prerequisites before main merge, deploy or live scanning.
