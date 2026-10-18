# LightUp · One-step independent human collaboration → next offline review

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

Two or more independent reviewers can use the same original private one-command human assessment workspace, each edit different original human planning slots, and export **one complete original human proposal bundle each**. The new `collaboration_cycle.py` combines the full-portfolio strict non-overlap merge with the existing complete next-source human review cycle in **one source-bound operator command**. The output is **one new private offline ZIP**; it does not require manually unpacking the intermediate merged proposal JSON or invoking a second CLI.

```sh
python3 assessment-portfolio/collaboration_cycle.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --original-choices /private/ORIGINAL-choices-B.json \
  --proposal-bundle /private/REVIEWER-1-all-human-proposals.json \
  --proposal-bundle /private/REVIEWER-2-all-human-proposals.json \
  --next-as-of 2026-10-19 \
  --output /private/NEW-private-collaborative-human-cycle.zip
```

The command invokes **the unchanged original source-workspace validators**, independently checks every original manifest and human choices source, and processes every contributor through the full original `workspace_return` admission. It refuses source membership drift, retained HOLD differences, changed prior human values and **any two contributors changing the same original (agenda, immutable slot)**, regardless of whether the proposed values match. The merged full-portfolio proposal is then passed **in memory** to the existing `review_cycle.build` which independently re-renders all original human agendas, creates NEW original choices for each source, creates a NEW standalone offline workspace and a revision board. Both phases must agree on the original HOLD and exact changed-human-slot counts before the atomic 0600 output is written.

The source loader now supports *either* one complete original-bound proposal **file** or the exact same bounded strict original-bound proposal **in-memory bytes** for composed internal workflows. The original CLI's `--proposal` and `--proposal-bundle` options and their existing external contract remain unchanged; in-memory bytes are subject to the same duplicate-key, complete source membership, false-authority, original SHA-256 and prior-value checks. This avoids temporary unverified copies and preserves all source-bound release limits.

Output:
- `index.html`: scriptless source-neutral contributor/agenda/slot human planning changes; no real identities.
- `merged-private-all-human-proposals.json`: private merged original all-agenda proposal in the same schema already accepted by the offline Review Studio and original return tools.
- `new-private-human-review-cycle.zip`: full new previous→next offline human review packet, including `next-human-workspace.zip` (with `workspace-home.html`), NEW original-schema human choices, private human change board, count-only transitions and original-source lineage record.
- `private-collaboration-manifest.json` and `private-cycle-bridge.json`: unsigned private source/collaboration byte correlations and explicit false consent/authority flags.
- `START-HERE.txt`: source-owner next steps and original human-only gates.

An optional previous original source-bound hypothetical capacity plan may be supplied with **both** `--previous-private-capacity-plan` and `--reconfirm-human-capacity`. As with `review_cycle.py`, it is independently revalidated and rebased onto the new planning date/source digests, never converted into an actual role assignment, executed job or review completion.

This is **offline human coordination**, not a scanner, model, target executor, remediation verification, customer consent, grant, or production release. Original source findings and evidence do not enter this new package. The entire ZIP stays PRIVATE. Contributor ordinals and SHA hashes are unsigned and are never reviewer authentication or permission. Actual execution/merge/release still requires original exact-head hosted/permanent named VPS CI, independent source-owner, security/privacy reviews, real separate client/operator consent with action-time revocation, #177/#182/#829 and HUMAN GO. No QA, tests, regressions or new process gates.
