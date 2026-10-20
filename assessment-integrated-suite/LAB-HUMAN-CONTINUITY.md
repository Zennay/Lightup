# LightUp · Original Lab Launchpad → PRIVATE HUMAN continuity

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Nothing in this software authorizes a scan, verifies ownership or consent, issues a grant, proves a finding, verifies a remediation, authenticates a team recipient or releases an assessment.

The source-owning [offline Lab Launchpad](../assessment-launchpad/README.md) remains unchanged. Its 0700 owner-only packets and native scope/Studio validators are re-admitted for every operation. Human review data is PRIVATE. Keep every input, downloaded CSV, intermediate and output outside the checkout in a directory mode **0700**, with files mode **0600**. Exact owner-private directories and no symlinks/hardlinks are required. Review in a local trusted browser, never upload original files or send workrooms without separately approved confidential delivery.

## Operator journey — integrated console

Open `python3 assessment-integrated-suite/console.py`; type `?lab`, `ALL`, `HELP`, or original numeric choices. Older options remain unchanged.

| Option | Original source-bound product | New HUMAN result |
|---|---|---|
| 52 | Prepare an original Lab Launchpad packet | One original numeric isolated-lab input proposal, never executed |
| 53 | Reopen an original Launchpad packet | Strict original source/Studio admission and private HTML |
| 54 | Compare 2 original Launchpad packets | Literal proposal added/absent/retained, not remediation |
| 55 | Summarize 3–8 original Launchpad packets | Scriptless PRIVATE proposed lab portfolio |
| 56 | Draft source-bound HUMAN Lab decisions | Offline original HUMAN stage/team/question Studio and CSV |
| 57 | Finalize original HUMAN CSV by explicit hand action | 0600 `PRIVATE-HUMAN-FINAL.csv`, result JSON and PRIVATE HTML (REVIEW_ONLY) |
| 58 | Resume saved HUMAN choices into a new Studio | Original source and review-room receipt re-admitted, no old source changed |
| **59** | Compare 2–8 distinct original **finalized HUMAN rounds** | Source-minimal HTML/JSON, `PRIVATE-HUMAN-CHANGES.csv`, continuous HOLD/NEEDS_INPUT across declared rounds |
| **60** | Split one original final HUMAN review into **team-only workrooms** | Separate 0600 scriptless pages **and CSVs** only for each assigned team; private operator directory |
| **61** | Admit a HUMAN team response into a new **complete candidate** | Separate 0700 room containing `PRIVATE-HUMAN-CANDIDATE.csv`, minimal decision summary and private receipt; no automatic original FINALIZE |

### HUMAN history — option 59

Select the **same** 3–8 original Launchpad packets and 2–8 distinct original 0700 finalized HUMAN review rooms in your explicitly declared order. Every original packet, final 0600 CSV and final 0600 summary is re-admitted against the exact same original Lab/Studio source digest and HUMAN row contract. Repeated byte-identical decisions are not counted as extra rounds. History outputs never include source paths/hashes/URLs, credentials or free HUMAN question text. Stage/team transitions and whether a private question changed are visible; order is **operator-declared, not proven time** and HOLD streaks are not severity or elapsed duration.

```sh
python3 assessment-integrated-suite/lab_review_history.py \
  --packet /private/plan-1 --packet /private/plan-2 --packet /private/plan-3 \
  --final-room /private/final-human-a --final-room /private/final-human-b \
  --private-parent /private --folder private-lab-human-history \
  --human-confirm 'BUILD PRIVATE LAB HUMAN HISTORY'
```

### TEAM-only workrooms — option 60

One original finalized 0700 HUMAN result is the ONLY source for stage/team/question decisions. Each source packet is independently re-opened through the original Lab Launchpad before using a HUMAN row. The resulting owner-only 0700 room has `OPEN-PRIVATE.html` (owner directory and counts), `PRIVATE-HUMAN-TEAM-MANIFEST.json` (unsigned original source fingerprint and pinned original full FINAL CSV hash, **PRIVATE**), and a read-only `TEAM-<team>.html`, an **offline editable**
`TEAM-<team>-EDITOR.html` and a matching source-bound
`TEAM-<team>-DRAFT.csv` for each assigned team. Each editor
shows only that team's originally assigned rows, lets a human alter only
HUMAN stage or bounded PRIVATE question, filters displayed stages,
and downloads the **complete** original team-only CSV (even when filtered).
Inline CSS/JavaScript is SHA-256-CSP pinned with no network, storage,
recipient or delivery side effect; native option 61 independently
re-admits any returned CSV. The owner-only HTML index links to each
read-only worklist and its corresponding PRIVATE editor. A page/CSV contains **only** that team's assigned packet slots, HUMAN stage and confidential HUMAN question. The owner-only `TEAM-unassigned-operator-only` group is never automatically assigned or sent. No original lab addresses are in any team page.

```sh
python3 assessment-integrated-suite/lab_review_team_handoff.py \
  --packet /private/plan-1 --packet /private/plan-2 --packet /private/plan-3 \
  --final-room /private/final-human-b \
  --private-parent /private --folder private-lab-team-workrooms \
  --human-confirm 'BUILD PRIVATE LAB TEAM HANDOFF'
```

**No recipient is authenticated or contacted.** Every generated team file remains owned by the source operator. An actual human must separately verify authorized recipient identity and confidentiality before sharing anything. A handoff is never a grant or assessment approval.

### Strict HUMAN team response — option 61

A team may **manually** edit its own original team DRAFT CSV and return it through a **separately approved PRIVATE channel**. The local owner must place returned CSV under 0700/0600 custody before re-admission. The team may change only `human_stage` and `human_question` of the exact originally assigned slots. It cannot change `human_team`, source fingerprint, slot count, row order, original client asset, another team's tasks, or authority fields. Native parser rejects unsupported stage, unassigned stage for a team, multiline controls, unsafe spreadsheet formula prefixes and oversized questions.

```sh
python3 assessment-integrated-suite/lab_review_team_return.py \
  --packet /private/plan-1 --packet /private/plan-2 --packet /private/plan-3 \
  --final-room /private/final-human-b \
  --handoff-room /private/private-lab-team-workrooms \
  --team Security \
  --response-csv /private/received/PRIVATE-SECURITY-TEAM-RETURN.csv \
  --private-parent /private --folder private-security-team-candidate \
  --human-confirm 'ADMIT PRIVATE LAB TEAM RETURN'
```

The return producer re-admits **all** original owner packets, original final review summary and rows, exact handoff manifest and unchanged **original team-only DRAFT** against an unsigned original-final full CSV SHA-256. Only the explicitly selected team's rows may be replaced. The **candidate is NOT a finalized HUMAN review**.

For actual human reconciliation, use option **58** with the **original HUMAN Studio review room** and the newly generated `PRIVATE-HUMAN-CANDIDATE.csv`. The original source-owning packets and original review-room receipt must again match. The next finalization is a **separate deliberate option 57**, not performed by receiving a team answer. The newly created candidate can never silently revise another team's decisions or the previous finalized room.

## Source and release limitations

An unchanged SHA-256 is unsigned byte evidence **only**, never independent producer authentication or current consent. Manually ordered reviews cannot prove chronology, tenant identity, operational incident duration, security regression or remediation. Browser-only assets and CSV downloads never convey guaranteed 0600 custody. Never assume HUMAN text is appropriate to disclose externally.

Exact-head hosted and permanently named VPS CI, original source-owner review, independent browser/privacy/security signoff, original #177/#182/#829 controls, **separately authenticated current client and operator consent with revocation-at-use**, and explicit **HUMAN GO** remain required before any actual scan, merge or deployment. No QA, security validation suite, live target, network call, model, grant or external dispatch is part of these offline workflows.
