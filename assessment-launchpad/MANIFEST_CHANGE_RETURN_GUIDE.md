# LightUp · PRIVATE HUMAN manifest-delta return

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.** This is an entirely offline review workflow. Nothing here performs assessment, scans, network calls, authorization, grant, client/operator identity verification, consent, revocation verification or HUMAN GO. Changes in manifest slots are not vulnerability findings or proof of remediation.

## Complete browser → native → read-only reopen flow

The existing `manifest_change_desk.py` produces a source-bound PRIVATE before/after comparison and its original `lightup-private-manifest-delta.csv`. Use the bundled `manifest_change_review.html` locally to import **that** CSV, edit the permitted HUMAN follow-up stages, then click **Export full HUMAN follow-up CSV**. The browser downloads a file named **`lightup-private-manifest-human-follow-up.csv`**; the downloaded CSV contains only change states, before/after ordinals and HUMAN review stages. The browser cannot prove original source authenticity or set private file permissions.

Move this CSV into a **new separate** private directory and make it owner-only. Preserve its exact downloaded bytes, including the original row order and all rows, even unchanged ones:

```sh
mkdir -m 700 "$HOME/private-manifest-answers"
mv "$HOME/Downloads/lightup-private-manifest-human-follow-up.csv" "$HOME/private-manifest-answers/"
chmod 600 "$HOME/private-manifest-answers/lightup-private-manifest-human-follow-up.csv"
mkdir -m 700 "$HOME/private-manifest-return"
python3 assessment-launchpad/manifest_change_response.py \
  --before-dir "$HOME/private-manifest-before" \
  --after-dir "$HOME/private-manifest-after" \
  --change-dir "$HOME/private-manifest-delta" \
  --answers-dir "$HOME/private-manifest-answers" \
  --output-dir "$HOME/private-manifest-return" \
  --explain-hold
```

All of the source, delta, answers and output directories must exist, be current-user-owned, mode 0700, and be separate. The three produced result files are mode 0600 and only written into an **empty** directory:

- `lightup-private-manifest-human-return.json`: canonical PRIVATE JSON with source-bound SHA-256 references, original ordinal rows, review stages, fixed counts and explicit `false` authority/consent/release flags.
- `lightup-private-manifest-human-return.html`: scriptless, network-denying, CSP-pinned local HUMAN review table without endpoints, paths or filenames.
- `lightup-private-manifest-human-counts.csv`: stage totals only, without original source values.

To reopen the **same** saved return without changing files, retain the exact original manifests, delta, answers CSV and all result files, and run:

```sh
python3 assessment-launchpad/manifest_change_response.py \
  --before-dir "$HOME/private-manifest-before" \
  --after-dir "$HOME/private-manifest-after" \
  --change-dir "$HOME/private-manifest-delta" \
  --answers-dir "$HOME/private-manifest-answers" \
  --verify-output-dir "$HOME/private-manifest-return" \
  --explain-hold
```

The native receiver reopens the original policy-admitted saved before/after bundles and the **existing exact private delta result** through `manifest_change_desk.py` before accepting edits. Each incoming row must match exactly the original change state, before slot, after slot, `REVIEW_ONLY` marker and order. Only `NOT_REVIEWED`, `REVIEWED`, `FOLLOW_UP`, and `NOT_APPLICABLE` are accepted; none is an approval or execution decision. Duplicate/missing/reordered original rows, unknown statuses, malformed/oversized files, non-private files, unexpected additional files, overlapping output trees or source drift are rejected. Source and edit bytes are re-admitted immediately before private publication; output is exclusive no-overwrite, and exact reopen compares every produced byte.

The source and answer digests are **unsigned local consistency binding only**. Source authenticity, actual approval, authentic separately obtained current client/operator consent, action-time revocation checks, independent security/privacy/source-owner review and explicit HUMAN GO remain separate requirements. This product must not be merged, deployed or used for target contact while release gates are held.

## Follow-up progress between two HUMAN rounds

When another person or the same reviewer edits the original HUMAN CSV in a **new separate** 0700 answers directory and saves a second native HUMAN return in its own 0700 directory, the companion `manifest_change_rounds.py` provides an original-row-aware PRIVATE change ledger. It does **not** interpret status changes as permission, validated findings, mitigation or approval.

```sh
mkdir -m 700 "$HOME/private-manifest-human-rounds"
python3 assessment-launchpad/manifest_change_rounds.py \
  --before-dir "$HOME/private-manifest-before" \
  --after-dir "$HOME/private-manifest-after" \
  --change-dir "$HOME/private-manifest-delta" \
  --first-answers-dir "$HOME/private-manifest-answers" \
  --first-return-dir "$HOME/private-manifest-return" \
  --second-answers-dir "$HOME/private-manifest-answers-2" \
  --second-return-dir "$HOME/private-manifest-return-2" \
  --output-dir "$HOME/private-manifest-human-rounds" \
  --explain-hold
```

Run with `--verify-output-dir` in place of `--output-dir` for read-only exact reopen against **both** original source-bound HUMAN return sets. The output is PRIVATE mode-0600 JSON, scriptless CSP-pinned HTML, and an ordinal-only CSV containing just HUMAN stages that changed. Previous/current stage counts, total unchanged rows, previous/current return digests and the original source bindings are included in the PRIVATE JSON. The original manifest URLs, source filenames and paths never appear in HTML or CSV. Both inputs are fully re-admitted using the prior native receiver; missing, modified or differently bound source material refuses publication. Operator-selected first/second order is **not authenticated chronology**.

Keep original HUMAN answer CSVs and each saved return byte-exact and separate. Downloads must have mode 0600. This comparison is an offline HUMAN workload view, not a new authorization system or assessment runner.
