# LightUp · Offline history across private human review cycles

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

The `review_cycle.py` workflow already creates one owner-private `private-revision-record.json` per original human-only review round. The new `revision_history.py` creates a **single offline visual review timeline for 2–12 consecutive ORIGINAL human review records** without needing original target data, source findings, client names, evidence, model access, executor, scanner or authorization.

```sh
python3 assessment-portfolio/revision_history.py \
  --cycle /private/ORIGINAL-cycle-01/private-revision-record.json \
  --cycle /private/ORIGINAL-cycle-02/private-revision-record.json \
  --cycle /private/ORIGINAL-cycle-03/private-revision-record.json \
  --output /private/NEW-human-review-history.zip
```

Every explicitly supplied private original record must match the exact original `lightup.assessment_portfolio_private_revision_cycle.v1` schema with strict duplicate-key-rejecting JSON, original cohort size 1–12, bounded human changes and four literal false authority flags. Every original source slot is exact, has a canonical 64-character SHA-256 correlation, and preserves its original `REVIEW_ONLY` / `HOLD` state. The entire sequence must have identical original source manifest identities and complete source order. Every later review receipt must have a **previous reference date equal to the last next date**, previous human choices SHA exactly equal to previous new choices SHA, previous original agenda SHA equal to last new agenda SHA, and unchanged original HOLD. Any gap, duplicate receipt, missing source, unexpected field, invalid change count or different cohort causes full HOLD and no output.

New private ZIP contains `index.html` (scriptless original human revision timeline and total human edits), `aggregate.html/json/csv` (source-neutral per-cycle human edit counts and planning reference dates, not original findings or verified fixes), `private-source-lineage.json` (owner-only original manifest/choices/agenda correlations for each stage, **unsigned**), and `START-HERE.txt`. All HTML escapes untrusted text and uses CSP SHA-256 pinned styles, with scripts/network disabled. Output uses the existing atomic 0600 no-overwrite original source publisher.

**Interpretation:** the history only tracks private human planning changes and source byte correlations. It is not a verified security benchmark timeline, a cryptographic attestation, original ownership evidence, audit of work performed, customer permission, consent, risk approval, SLA, remediation or GO. A changed original human stage/date does **not** mean a vulnerability was fixed, even if the next original source omitted it. Aggregate counts and reference dates may still be sensitive in small groups, so review sharing carefully. Real original source owner/security/privacy/CI/client+operator authorization with action-time revocation and explicit HUMAN GO remain mandatory for any real target activity or release.

Only the independently owned `assessment-portfolio/` paths are touched. No QA or test suites are included.

## Directly import complete previous review-cycle ZIPs

For original complete `review_cycle.py` output ZIPs you **no longer have to extract** any private intermediate JSON records. Use the separate mutually exclusive `--cycle-zip` option (repeat 2–12 in chronological review order):

```sh
python3 assessment-portfolio/revision_history.py \
  --cycle-zip /private/ORIGINAL-REVIEW-ROUND-01.zip \
  --cycle-zip /private/ORIGINAL-REVIEW-ROUND-02.zip \
  --output /private/NEW-private-human-history.zip
```

This route additionally admits each previous complete private ZIP against its original member whitelist, bounded stored-only/no-duplicate/no-encrypted layout, original in-ZIP strict revision record, nested full private source-bound workbench, exact next source map, each exact next original human choices SHA and agenda SHA; when optional hypothetical capacity continuation exists it is required to match the same new original agenda/date/status. Only after **all** ZIPs are consistent does it compare the human revision sequence. A ZIP fingerprint is unsigned and remains no proof of actual original identity, permission or outcome. The previous --cycle JSON route remains supported.

The complete ZIP admission also enforces the **entire** optional prior human Capacity Studio plan contract (exact original schema/fields, five canonical neutral roles, 0–100 integer hypothetical weekly capacities, 1–12 integer weeks, exact source slot SHA/status, false-only authority and 64 KiB plan size), not only its original source hash. Invalid capacity metadata HOLDs the complete history before producing an output. This is private planning source admission, not another release gate or genuine consent proof.
