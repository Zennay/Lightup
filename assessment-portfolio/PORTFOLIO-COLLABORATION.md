# Complete offline multi-reviewer portfolio collaboration

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

Several human reviewers may each open the same privately supplied **original one-command assessment workspace** and use **Export ALL original human proposals** to produce a complete original-agenda bound JSON. The new `portfolio_merge.py` accepts 2–12 such bundles and combines only **disjoint original agenda/slot edits**. It does not authenticate reviewer identities, decide which reviewer is right, validate a vulnerability, contact targets or change real source records.

```sh
python3 assessment-portfolio/portfolio_merge.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --original-choices /private/ORIGINAL-choices-B.json \
  --proposal-bundle /private/REVIEWER-1-all-human-proposals.json \
  --proposal-bundle /private/REVIEWER-2-all-human-proposals.json \
  --output /private/NEW-collaborative-human-proposals.zip
```

Every contributed bundle is checked independently through the **existing** `workspace_return.build` route: complete workspace original private agenda, current immutable original manifest, previous source-bound choices, exact original agenda re-render, original slot + old human prior state, bounded complete source membership, literally false permission/consent/dispatch/release flags and original retained HOLD. The original manifests, choices and workspace bytes are pinned and rechecked before any new output. Same input bundle twice is rejected. Contradictory source membership, missing agendas, incompatible source dates or any invalid proposal causes a complete HOLD.

Conflict boundary: if two different contributors edit **the same original (agenda, source slot)**, the entire merge is rejected without output, **even if they happen to submit identical values or change different human-only fields**. The source owner must independently reconcile such human disagreements; software cannot silently choose one revision, claim a consensus or infer an approval. Human-only edits to different slots are retained; untouched original stage, neutral role and proposed review date are copied from the immutable previous human source.

The new owner-private 0600 ZIP contains `merged-private-all-human-proposals.json` in the **same complete `lightup.assessment_portfolio_human_proposal_bundle.v1`** accepted by existing `workspace_return.py --proposal-bundle`, `review_cycle.py --proposal-bundle --next-as-of YYYY-MM-DD`, and the browser's **Restore ALL private proposals**. Its `private-collaboration-manifest.json` records unsigned original workspace/contributor SHA-256 byte correlations, contributor ordinal and source-slot field changes; `index.html` provides a scriptless source-neutral visual handoff. Reviewer ordinals are local numbering, **not user identity proof**.

The original complete workspace, all previous manifests/choices, every independent contribution and previous review cycle stay unchanged. A downstream operator must deliberately invoke the original receiver/next-cycle workflow with exactly the same separately held original source files. No automatic downstream application, customer evidence interpretation, role assignment, model, target request, grant, scan, consent or actual engagement. Even a non-conflicting private human proposal remains **REVIEW_ONLY or HOLD, never GO**.

Mandatory original hosted/permanent named VPS exact-head CI, source owner, independent security/privacy approval, real separate authenticated client/operator consent with action-time revocation, #177/#182/#829 integration and explicit HUMAN GO all remain required before real release or active assessment. No QA/regression/test suites are created or executed by this product workflow.

To generate the NEXT full offline human assessment workspace in the same operator action, use [collaboration_cycle.py](COLLABORATION-CYCLE.md) with the same original inputs and `--next-as-of YYYY-MM-DD`. It combines the conflict-free multi-human proposal and full source-bound new review cycle entirely in memory and publishes only a new private 0600 ZIP.

## When original human proposals conflict

The strict disjoint merge intentionally stops with HOLD if two reviewers modify the same original agenda/slot. Use the [independent original human mediation Studio](PRIVATE-MEDIATION.md) to display all such already-validated proposals and require an explicit human selection (including `keep original`) for each contested local source slot. Only after a human explicitly exports a NEW complete private bundle should the original human return/review-cycle CLI receive the result. Automatic merge rules stay unchanged.
