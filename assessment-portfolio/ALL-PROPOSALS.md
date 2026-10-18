# One-click original human proposal bundle

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

The local original-human-review Studio in the one-command assessment workbench now has two independent export workflows: its existing one-source private proposal JSON and a new **Export ALL original human proposals** button. The all-agenda button collects the local current human stage, neutral role and proposed date for each of the **1–12 original agendas**, including agendas not actively selected in the UI. It retains original agenda-slot ordering, source SHA-256 references and each item's old stage/role/date without changing any original input or making any network request.

The all-agenda export requires a separate explicit **all-sources human-only privacy/authority disclaimer** checkbox. Every proposed date must pass the existing canonical browser date check before the single download begins. The downloadable `lightup-PRIVATE-all-human-proposals.json` is one confidential JSON object of schema `lightup.assessment_portfolio_human_proposal_bundle.v1`: full source membership, one existing original human proposal per agenda, bound original agenda SHA-256, explicit reference date, and all four authority flags false. It contains private human notes and fingerprints, not genuine permission.

### Return all proposals directly — no manual per-agenda extraction

```sh
python3 assessment-portfolio/workspace_return.py \
  --workspace /private/ORIGINAL-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/CHOICES-A.json \
  --original-choices /private/CHOICES-B.json \
  --proposal-bundle /private/lightup-PRIVATE-all-human-proposals.json \
  --output /private/NEW-original-human-choices.zip
```

Or use the same `--proposal-bundle` argument with `review_cycle.py` and `--next-as-of YYYY-MM-DD` to obtain a full next interactive offline workbench **plus** the new original-schema human choices and historical change board. The previous individual `--proposal FILE` (repeat once per source) remains supported, but cannot be mixed with `--proposal-bundle`.

The Python bundle loader restricts input to a regular, no-follow ≤4 MiB JSON file; rejects ambiguous duplicate keys, invalid/missing/extraneous fields, inaccurate original source counts or sequence, wrong original reference date and mismatched original agenda SHA-256; requires the original exact human proposal shape and all authority flags false. It then reuses the **full unchanged original manifest/choices/agenda plus human proposal reconciliation**, regenerating original agendas from original files and checking byte identity before atomic nonoverwriting 0600 output. Any mismatch anywhere causes full HOLD; no partial publication or alteration to original files.

This is an offline human planning roundtrip only. Source fingerprints do not prove source identity, current consent, real authorization, verified findings, repairs, or release. No lab run, scan, target request, client data write, remediation command, token or grant is triggered. Original mandatory exact-head hosted/named VPS CI, original source-owner acceptance, independent privacy/security, genuine separately authenticated client/operator consent with action-time revocation and explicit HUMAN GO remain required before any main merge/release.

To continue editing later, open the **same original private source** Review Studio again and use **Restore ALL PRIVATE human proposals JSON** (plus the explicit acknowledgement) to load the exported bundle as a single atomic local operation before any further cross-agenda edits. See [RESTORE-ALL.md](RESTORE-ALL.md). No browser persistence or original data write occurs.
