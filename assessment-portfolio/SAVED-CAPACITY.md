# LightUp · Private Source-bound Human Capacity Plans

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD, NO GO.**

The existing independent offline [human capacity Studio](STUDIO.md) now provides two operator-initiated actions: **Download PRIVATE source-bound plan** and **Restore PRIVATE source-bound plan**. These actions allow human planners to resume their hypothetical role/week choices across browser sessions without browser persistence or modifying any original lab source.

The plan includes only original human source agenda ordinal, complete original agenda byte SHA-256, its original claimed HOLD or REVIEW_ONLY, original shared planning date, hypothetical 1–12 week horizon, neutral weekly role capacities 0–100, and four literally false authority fields. It does **not** include actual client evidence, findings or target IPs. Treat the source hashes as PRIVATE, not a proof of issuer authentication.

Restoring is **all-or-nothing**: all original source slots, digests and claimed statuses must equal the source-bound Studio's immutable initial sources. Reject unknown keys, missing sources, mismatched date, noncanonical weekly capacities or authority flags. The browser never silently promotes old human work to a valid current approval.

## Re-render a saved plan from original independent sources

Use the new CLI with the **same original agenda JSONs in the same order**:

```sh
python3 assessment-portfolio/capacity_plan.py \
  --agenda /private/ORIGINAL-A-AGENDA.json \
  --agenda /private/ORIGINAL-B-AGENDA.json \
  --as-of 2026-10-18 \
  --private-plan /private/lightup-PRIVATE-source-bound-review-capacity.json \
  --format private-html \
  --output /private/NEW-human-capacity-review.html
```

Original source byte integrity, original agenda counts/stage/date admission, claimed HOLD, role budget 0–100 and exact original date are rechecked by the unchanged original source readers and the new private plan admission. Use `--format aggregate-html` or `--format aggregate-csv` for anonymous human-only workload counts; still consider small-group reidentification before sharing.

All destinations are exclusive original-publisher 0600 output files with no overwrite. Exit 2 = original human REVIEW_ONLY planning artifact, exit 3 = retained original HOLD or rejected source/plan, never automatic permission.

No original authorization/scanner/model/assessment production code was modified. There is no request to a target, security finding verification, client/operator consent attestation, scheduled real review, grant, human GO, or production deployment. Original exact-head hosted and permanent named VPS CI, independent original source-owner/privacy/security review, actual separately authenticated client/operator consent including at-use revocation and explicit HUMAN GO remain mandatory.
