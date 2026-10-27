# LightUp · Offline Human Review Capacity Outlook

**DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY.** This is a human discussion aid using only the **unchanged original** privately exported archive agenda JSONs. No scans, models, client permissions, grants or automatic assignments.

## A complete second operator workflow

Start with the *same* original private human agenda outputs described in [README.md](README.md). Supply a human hypothetical capacity (review touchpoints per seven-day window) for each neutral role you want to model:

```sh
python3 assessment-portfolio/capacity.py \
  --agenda /private/original-a-agenda.json \
  --agenda /private/original-b-agenda.json \
  --as-of 2026-10-18 \
  --role-capacity operator=5 \
  --role-capacity reviewer=3 \
  --role-capacity privacy=2 \
  --role-capacity source_owner=2 \
  --weeks 8 \
  --format private-html \
  --output /private/NEW-role-capacity-board.html
```

Open the complete offline local HTML. Human operators see the **original source-slot and agenda ordinals**, original stages, neutral roles, original proposed date categories, and which hypothetical weekly review-touchpoint the selected capacity could accommodate. The report distinguishes tasks with no available hypothetical slot; it never asserts that a review was actually scheduled, assigned, performed, finished or approved.

For a separately reviewed anonymized role-workload handoff:

```sh
python3 assessment-portfolio/capacity.py \
  --agenda /private/original-a-agenda.json \
  --as-of 2026-10-18 \
  --role-capacity reviewer=4 \
  --weeks 4 \
  --format aggregate-csv \
  --output /private/NEW-human-capacity-aggregate.csv
```

Also available: `--format aggregate-html`, which omits source slots, exact original dates and individual human stages. Aggregate role counts may still expose sensitive small-group information.

All other unspecified role capacities are **zero**, never guessed. Each supplied role can only appear once; allowed neutral roles are the unchanged original `unassigned`, `source_owner`, `reviewer`, `privacy`, and `operator`. Capacity ranges from 0 to 100 per role per week and the hypothetical horizon is 1–12 seven-day windows. Workload is prioritized according to **original proposed date category, then date/stage and stable original agenda/source slot**. It does not change original source states or presume work is done. Missing slots remain human attention items, not repaired findings.

The planner reuses the independent strict original agenda admission in `portfolio.py`, including original no-follow bounded reads, untrusted JSON duplicate-key checks, exact row/count/date admission and no-authority flags. Publication reuses the original 0600 fsynced no-overwrite publisher. Nonzero exit 2 is REVIEW_ONLY, exit 3 retains source HOLD or rejects invalid inputs; never a permission indication.

Original exact-head hosted and named permanent VPS CI, original source-owner and independent privacy/security approvals, separately authenticated client/operator consent including revocation at use and explicit HUMAN GO remain absolute release prerequisites. No QA/testsuites or actual runtime evaluation are added or run.
