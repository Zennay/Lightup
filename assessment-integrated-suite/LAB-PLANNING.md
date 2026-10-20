# LightUp · Original Lab Launchpad → PRIVATE HUMAN Review

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline review workflow, not an active assessment, authorized asset, verified finding, client report, scanning schedule or release.

## One complete local product workflow

The original source-owner [Lab Launchpad](../assessment-launchpad/README.md) already prepares source-admitted numeric isolated-lab inputs. The integrated assessment console now exposes its exact installed source-owner functionality without copying its original validators.

| Native console | What it does | Original policy |
|---|---|---|
| **52** Prepare lab plan | One original `targets.txt` (optionally original Studio catalog and scenario) → new PRIVATE original Launchpad workroom | Original `build.py` and immutable `LabScenario`/URL admission |
| **53** Reopen lab plan | Validate the unchanged original packet's local source fingerprint and owner-private files | Original `reopen.py` |
| **54** Compare two plans | Human-only source revision (added/absent/retained proposal URLs) | Original `compare.py` |
| **55** Lab plan portfolio | Three to eight separate original packets → one PRIVATE source-bound historical proposal desk | Original reopen and compare readers |
| **56** HUMAN review studio | Three to eight original packets → interactive offline HUMAN status/team/question editor with exact original-source-bound CSV | Original reopen plus owner-private 0700/0600 reader |
| **57** Finalize HUMAN choices | Explicit completed private CSV + same original packets → separate source-bound PRIVATE HUMAN result | Original reopened source identity + strict native CSV admission |

Nothing changes the existing original source-owner branches, authorization domain, scanner, original lab CLI, model providers, tests or security gates.

## Use console navigation

Run the existing local foreground console:

```sh
python3 assessment-integrated-suite/console.py
```

Use `?lab`, `ALL` or `HELP` to discover actions, or type exact numbers **52–57**. Each original action requires explicit HUMAN confirmation before invoking the original **non-scanning** producer.

The standalone native CLI also supports:

```sh
# Existing 0700 PRIVATE parent and already owner-private 0600 file are required.
python3 assessment-integrated-suite/lab_plans.py prepare \
  --targets-file /private/targets.txt \
  --private-parent /private \
  --folder original-lab-plan-a \
  --human-confirm 'PREPARE PRIVATE LAB PLAN'

# Re-open only original on-disk source material; no target execution.
python3 assessment-integrated-suite/lab_plans.py reopen \
  --packet /private/original-lab-plan-a \
  --human-confirm 'REOPEN PRIVATE LAB PLAN'

# A different original packet must already exist; order is HUMAN-declared.
python3 assessment-integrated-suite/lab_plans.py compare \
  --before /private/original-lab-plan-a \
  --after /private/original-lab-plan-b \
  --private-parent /private \
  --folder original-lab-diff \
  --human-confirm 'COMPARE PRIVATE LAB PLANS'

# Requires THREE to EIGHT original independently source-admitted packets.
python3 assessment-integrated-suite/lab_plans.py portfolio \
  --packet /private/original-lab-plan-a \
  --packet /private/original-lab-plan-b \
  --packet /private/original-lab-plan-c \
  --private-parent /private \
  --folder original-lab-portfolio \
  --human-confirm 'BUILD PRIVATE LAB PORTFOLIO'

# NEW: source-bound HUMAN review Studio, not a customer authorization.
python3 assessment-integrated-suite/lab_plans.py review-prepare \
  --packet /private/original-lab-plan-a \
  --packet /private/original-lab-plan-b \
  --packet /private/original-lab-plan-c \
  --private-parent /private \
  --folder original-lab-human-studio \
  --human-confirm 'PREPARE PRIVATE LAB HUMAN REVIEW'
```

Open the new `/private/original-lab-human-studio/OPEN-PRIVATE.html` *locally* in a trusted browser. All HUMAN rows start **UNASSESSED**. Choose an explicit HUMAN stage (UNASSESSED, HOLD, NEEDS_INPUT, HUMAN_REVIEW or HUMAN_FOLLOWUP), optional HUMAN team, and optional bounded question. The browser writes no persistent data. Its Download action requests a complete source-bound CSV, **but does not prove the download happened**. Browser download permissions are not necessarily 0600. Deliberately move the completed file into a controlled owner-only 0700 parent, chmod it 0600, then finish with the original exact source selection:

```sh
python3 assessment-integrated-suite/lab_plans.py review-finalize \
  --packet /private/original-lab-plan-a \
  --packet /private/original-lab-plan-b \
  --packet /private/original-lab-plan-c \
  --review-room /private/original-lab-human-studio \
  --human-csv /private/HUMAN/PRIVATE-LAB-HUMAN-DECISIONS.csv \
  --private-parent /private \
  --folder original-lab-human-final \
  --human-confirm 'FINALIZE PRIVATE LAB HUMAN REVIEW'
```

The final output is a new 0700 PRIVATE workroom with its own 0600 scriptless HUMAN brief, decisions CSV and counts-only JSON. The source reader admits the exact original Lab Launchpad packets again, rejecting changed original source identities, malformed decision rows, stage/team violations and unsafe CSV formula prefixes. Every emitted authority/consent/verification flag remains false. This workflow does **not** promote HUMAN decisions to PASS, verify a finding, open sockets, run `lightup lab-assess`, or contact a client.

## Confidentiality and source limits

All original endpoint URLs, Studio catalogs, source fingerprints, local paths, HUMAN questions, browser reports and CSVs are PRIVATE. Place them only under trusted owner-owned directories outside the checkout with directory mode **0700** and file mode **0600**. The software bundle ships **no** original client material, private source files, stored operator session or real assessment evidence.

The portfolio's owner-private detailed JSON includes proposal URLs. Its separate counts JSON deliberately omits URLs and identities; even anonymous results are **not** released externally automatically. The source identity SHA-256 is **unsigned** and is only byte revision evidence, **not** verified provenance. Original proposals selected in “earlier/later” order do not demonstrate real chronology or a shared tenant. Missing proposals do not mean fixed, remediated, revoked, decommissioned or cleared.

Before any real work the original hosted + permanently registered named VPS exact-head CI, source-owner approval, independent browser/privacy/security reviews, required #177/#182/#829 admission and verified *separate, current* client and operator consent including **at-use revocation**, plus explicit **HUMAN GO**, remain obligatory. Never override or bypass a gate, and never execute a scanner in this planning workflow.
