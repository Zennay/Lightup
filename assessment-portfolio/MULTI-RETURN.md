# LightUp · Multi-source Private Human Return

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is the multi-source partner to the [original human proposal return](REVIEW-RETURN.md), never an assessment, scan, grant, finding validator or release workflow.

## Operator's single private review-room handoff

When two to twelve independent original archives have their own unchanged original manifests, original human choices, original source-bound agenda JSONs and browser-exported human-only proposals, the operator can prepare **one owner-private ZIP** with matching original-schema replacement choices and a non-authorizing source inventory:

```sh
python3 assessment-portfolio/multi_return.py \
  --original-manifest /private/archive-A.json \
  --original-manifest /private/archive-B.json \
  --original-choices /private/choices-A.json \
  --original-choices /private/choices-B.json \
  --original-agenda /private/agenda-A.json \
  --original-agenda /private/agenda-B.json \
  --proposal /private/proposal-A.json \
  --proposal /private/proposal-B.json \
  --output /private/NEW-private-multi-human-return.zip
```

The repeated argument groups pair by ordinal source: each first `--original-manifest`, `--original-choices`, `--original-agenda` and `--proposal` belong to source #1; each second belongs to #2. Missing or extra files HOLD the *entire* proposal batch. Original archives cannot appear twice in the same handoff.

The finished private ZIP contains:

- `original-human-choices-01.json`, `original-human-choices-02.json`, etc. — complete owner-private ORIGINAL `lightup.archive_human_followup.v1` JSON, with only human stage, neutral role and proposed review date changes; original source slot hashes kept intact.
- `index.html` — original-schema scriptless private source-slot inventory, new original choices member name, original claimed source HOLD and number of edited human slots. No browser interaction or target connections.
- `private-manifest.json` — each original immutable manifest SHA, output choices SHA and private source HOLD marker; literal authority flags false.
- `START-HERE.txt` — separate human handoff instructions.

The original manifest, target/finding/evidence files and complete assessment lab cases are NOT bundled. The resulting ZIP is still **PRIVATE** because source hashes and human follow-up details are sensitive. A SHA proves byte correlation, **not authentic issuer/ownership, permission or verified lab evidence**.

### No partial human application

Each original source is independently admitted by the actual unchanged original archive+choices validators and strict [single-source proposal return](REVIEW-RETURN.md) before any output is published. A stale human prior value, source hash drift, missing original membership, duplicate source manifest, malformed source, wrong role, date or extra authority field makes the **whole batch HOLD**. No partial output is created; on success the entire ZIP is atomically published as a single new owner-only `0600` file without overwriting. Each recipient chooses the matching original manifest and separately runs original `assessment-archive/agenda.py` on the extracted corresponding original-schema choices. Nothing is implicitly scheduled, completed or auto-applied.

Exit code 2 = all original sources are REVIEW_ONLY human planning; 3 = at least one original HOLD or rejected source. No success code authorizes execution.

Original PR owners, core assessment, original grants and CI are untouched; no QA, regression or test suite, real target, model or scanner is written or run. Mandatory exact-head hosted/permanent named VPS CI, original source-owner + independent privacy/security review, separately authenticated current client/operator consent with revocation at use and explicit HUMAN GO all remain required.
