# LightUp · Human-mediated portfolio review → source-bound NEXT offline cycle

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

When independent human reviewers disagree on the same original agenda/source-slot, **the automatic `portfolio_merge.py` continues to reject the conflict**. Use [portfolio_mediation.py](PRIVATE-MEDIATION.md) first to create the local HTML mediation Studio from all original independently validated full-proposal bundles. A human selects one candidate or keeps original human planning values for **each contested slot**, explicitly acknowledges that no grants/findings/consent are involved, and exports `lightup-PRIVATE-resolved-original-human-proposals.json`.

The new `mediation_return.py` completes the remaining secure operator workflow **in one command** using this separately exported human resolution and the exact original inputs:

```sh
python3 assessment-portfolio/mediation_return.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --original-choices /private/ORIGINAL-choices-B.json \
  --proposal-bundle /private/REVIEWER-1-all-human-proposals.json \
  --proposal-bundle /private/REVIEWER-2-all-human-proposals.json \
  --resolved-bundle /private/lightup-PRIVATE-resolved-original-human-proposals.json \
  --next-as-of 2026-10-19 \
  --output /private/NEW-private-mediated-human-cycle.zip
```

The receiver does **not trust the browser export as an approval**. It independently calls the original full-portfolio mediation admission to re-admit every original manifest, choices, workspace and all contributor proposals. It loads the resolved JSON with the same strict `proposal_bundle.load` original source/date/count/false-authority admission. For every original slot, the proposed final human `stage/next_role/review_date` must equal **either the exact prior human values or one exact tuple from the independently admitted candidate proposals for that slot**. No extra changed fields, changes to uncontested slots never proposed by any contributor, arbitrary third-party values, replaced original source slots or fake reviewed findings can be introduced. The original contributor registry and contested-slot membership must still match. (Only the local browser can evidence that the human interacted with its controls; this CLI deliberately does NOT claim authenticated human identity or intent.)

After full admitted source/choice checks, the unchanged `workspace_return` independently confirms the exact original source-bound human return and the existing `review_cycle` builds the NEXT complete private original-schema human choices and offline workspace. All phases require the same original HOLD and exact source-slot change count, while the resolved proposal bytes are kept stable throughout the operation. The normal `publish()` creates **one new atomic non-overwriting 0600 ZIP** only after all parts succeed.

The return ZIP contains:
- `index.html`: scriptless original source-slot mediation overview with disposition and matching contributor ordinals, **never authenticated identities**.
- `private-human-mediation-record.json`: canonical source-neutral human resolution record with false-only authority.
- `resolved-original-human-proposals.json`: the identical complete owner-private human-only proposal which passed full validation.
- `new-private-human-review-cycle.zip`: the complete newly generated original human review cycle including `next-human-workspace.zip`, new original source-bound human choices, source-neutral change board and privately linked original review metadata.
- `START-HERE.txt`: instructions and explicit DRAFT/HOLD/NO GO.

The operator may also explicitly continue a previous hypothetical neutral-role capacity plan via **both** `--previous-private-capacity-plan` and `--reconfirm-human-capacity`, as in the existing original `review_cycle.py`. Neither step assigns human personnel or real jobs.

**Original source evidence, client assets and targets never enter this workflow.** Original manifests, choices, signed or unsigned source material and prior offline reviewer bundles are not modified. Reviewer ordinals and SHA hashes are unsigned byte correlations, not authentication or proof of authorization, vulnerability fixes, original source truth or actual decisions. Original source owner, independent security/privacy review, real separate authenticated client/operator permission with action-time revocation, original hosted and permanently registered named VPS exact-head CI, #177/#182/#829 integration and explicit HUMAN GO all remain mandatory for any real assessment, merge or deploy. No QA/regression/test suites were written or run.
