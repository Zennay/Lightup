# LightUp · Private original human mediation Studio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.** This is a standalone offline local-human planning editor, not real client consent, authenticated reviewer sign-off, remediation verification or authorization.

The conflict-safe multi-human merge `portfolio_merge.py` deliberately refuses overlapping changes on the same original agenda/slot. Independent reviewers still need a usable way to **see what conflicted and explicitly choose a human-only next value**. The new `portfolio_mediation.py` accepts the exact same 2–12 independently exported **complete private all-agenda human proposal JSONs** plus the separately held **unchanged original workspace, manifest and choices files**. Unlike the strict auto-merge it permits conflicting *human proposals for display only*, then publishes one owner-private 0600 standalone offline `HTML` mediation Studio.

```sh
python3 assessment-portfolio/portfolio_mediation.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --original-choices /private/ORIGINAL-choices-B.json \
  --proposal-bundle /private/REVIEWER-1-all-human-proposals.json \
  --proposal-bundle /private/REVIEWER-2-all-human-proposals.json \
  --output /private/NEW-private-human-conflict-studio.html
```

**Every contributor is independently re-admitted through unchanged `workspace_return.build`**, original manifest/choices and original private agenda re-render: exact original slot/prior human values, source SHA membership, original HOLD, complete bounded JSON, and all four literal false authority flags. Original manifest/choices/workspace SHA snapshots are re-read to catch input drift. Duplicate contributor bundles and any incompatible previous source fail closed with no output. Original findings, lab targets, client identities, evidence or credentials are never opened by the mediator.

The browser receives only source-neutral agenda/slot ordinals, previous human stage/neutral next role/proposed date, candidate new values and unsigned contributor sequence numbers. A single contributor edit is preselected only as a *human-only local draft*, not accepted as true or completed. **Conflicted original slots have no default winner.** A real human must explicitly select one named-by-number candidate or **keep the original human values** for *each* contested source slot. The page shows total conflicts, unresolved rows, proposal changes and decisions to retain originals. While any original slot is contested and unanswered, export stays disabled. A reset discards all local conflict choices; nothing alters original files.

When all conflicts are explicitly resolved, a **separate human-only disclaimer checkbox** is required to export `lightup-PRIVATE-resolved-original-human-proposals.json` in the exact existing complete `lightup.assessment_portfolio_human_proposal_bundle.v1` shape, with **every original agenda and every old human slot retained**. The file is accepted by the existing `workspace_return.py --proposal-bundle` and `review_cycle.py --proposal-bundle` only after their *independent* strict original source admission. It may also be imported into the ORIGINAL Review Studio via Restore ALL for further private discussion. The browser performs no original input overwrite, disk writes other than explicit download, network, remote script, browser persistence, task dispatch, grant or scan.

The output HTML embeds only bounded validated original human-only planning metadata. Script and CSS are CSP-SHA-pinned, untrusted embedded JSON cannot close the inert data script, and no external dependencies are used. This is an **unsigned** owner-private source-neutral coordination record: reviewer ordinals **do not authenticate** a reviewer, original source SHA is not a cryptographic source signature, and choices do not imply verified findings/consent or actual work. Original exact-head hosted/permanent named VPS CI, source-owner approval, independent security/privacy review, real separately authenticated client/operator permission with action-time revocation, #177/#182/#829 and explicit HUMAN GO remain mandatory for any real assessment or release.

### Complete the mediated return in one source-bound step

After the original human reviewer explicitly exports a complete private all-agenda resolution bundle, use [mediation_return.py](MEDIATION-RETURN.md) to re-admit the unchanged original workspace, all original manifests/choices and every independently contributed full human proposal, then accept **only originally offered candidate values or the original prior human values**. It generates a NEW complete review cycle + private conflict disposition ZIP, without making any original source or authorization changes.
