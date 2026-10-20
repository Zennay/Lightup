# LightUp · Original-Schema Human Proposal Return

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This feature connects human-only review edits in the standalone offline browser Studio back into the **unchanged original** archive's source-bound human choices schema. It does not alter any original lab benchmark, target, asset, grant, finding, evidence, permission, scanner, retest or approval.

## Full operator workflow

1. Create original owner-private JSON agendas as in [README.md](README.md) using `assessment-archive/agenda.py --manifest ORIGINAL.json --choices ORIGINAL-HUMAN.json --as-of ... --format json`.
2. Generate the standalone private editing Studio (or open the included `original-human-review-studio.html` in your portfolio ZIP):

```sh
python3 assessment-portfolio/review_studio.py \
  --agenda /private/ORIGINAL-AGENDA.json \
  --as-of 2026-10-18 \
  --output /private/NEW-private-review-studio.html
```

3. In the offline Studio choose the original agenda; edit only the human stage, neutral role and proposed date. Select individual source slots, or select visible rows and bulk-apply only human fields. Inspect the live before/after private change preview. No original source content is editable. Export a **PRIVATE** human proposal JSON via explicit manual download.
4. Return that human-only change proposal to the **original format**, without changing an existing file:

```sh
python3 assessment-portfolio/proposal_return.py \
  --original-manifest /private/ORIGINAL-MANIFEST.json \
  --original-choices /private/ORIGINAL-HUMAN.json \
  --original-agenda /private/ORIGINAL-AGENDA.json \
  --proposal /private/lightup-PRIVATE-human-proposal-agenda-1.json \
  --output /private/NEW-source-bound-HUMAN-choices.json
```

5. Use the **original unchanged authoritative human-only renderer** to produce a new human agenda from the *new* private choices and original manifest:

```sh
python3 assessment-archive/agenda.py \
  --manifest /private/ORIGINAL-MANIFEST.json \
  --choices /private/NEW-source-bound-HUMAN-choices.json \
  --as-of 2026-10-18 \
  --format html \
  --output /private/NEW-human-agenda.html
```

There is **no automatic accept, merge or overwrite**; operator chooses each explicit private source and new destination.

### Original-source admission

The receive CLI reuses the actual original `archive.py` strict manifest reader, original `followup.py` strict choices validator, original source-bound agenda validator and original fsynced exclusive 0600 publisher. The proposal must match **exact raw original agenda SHA-256**, original date, original source status, all original slot IDs and counts, all prior human stage/role/date values, and each original private manifest `source_sha256` correlation. Any stale choice, renamed/removed source row, changed original lab source, conflicting original manifest, extra field, duplicated JSON key, malformed date or forged authority flag produces HOLD and no output. The original manifest/choices files are read-only.

Only the fields `stage`, `next_role` and `review_date` may change. Every source slot must remain present. Only the original stage/neutral role vocabularies apply. A proposed review date must be either `null` or exact ISO calendar `YYYY-MM-DD` in 2020–2100. All proposals are human planning notes with literal authority flags false. Human notes may be untrusted and unsigned: source digest is byte correlation, not identity verification.

The return output uses the actual **original `lightup.archive_human_followup.v1`** schema, reusing the immutable `manifest_sha256`, source slot/source byte digests and exact false authority flag set. An ordinary return does **not** publish a new assessment finding, evidence or safety verdict.

Exit 2 is human-only REVIEW_ONLY, exit 3 retains original HOLD or rejects incompatible input; no success code can authorize execution.

### Privacy and release

The private Studio contains original source-byte fingerprints and source slots, which **must not** be publicly distributed. All browser edits live in volatile browser memory; no network, localStorage, cookie, data uploads, model, scanner, target requests or external scripts exist. A private exported JSON is not an authenticated client/operator instruction.

Original exact-head hosted and permanently registered named VPS CI, original source owner, independent privacy/security review, current independently authenticated client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory before active work or a main/deploy merge. No QA or regression suite is created or run.

### Browser-side private draft continuation and multi-row review

Within the self-contained HTML, the operator may select specific visible original slots, apply one human stage/neutral role/proposed date to those selected slots, clear the date or reset an agenda. The live local private change preview shows old vs proposed fields for every modified slot. The local browser can also **restore a previously exported PRIVATE proposal** of at most 256 KiB. Restore atomically requires exactly the original agenda SHA, reference date, all original source slot membership and all prior original human values, with only canonical human stage, role and date changes, and all authorization flags literally false. On mismatch, current in-memory work is left unchanged and the import is marked HOLD. Original sources are never modified by the browser. The strict server-side ORIGINAL-schema CLI remains required for any real human planning return. Browser persistence and network calls remain disabled.
