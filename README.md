# LightUp

LightUp is an AI-assisted security validation platform for **owned or explicitly authorized systems**.

Its long-term product promise is:

> **Find what is vulnerable today, and prove whether the change you are about to ship makes you vulnerable tomorrow.**

That means LightUp is being built around two complementary lanes:

- **Current Security** — evidence-backed assessment of today's vulnerabilities, misconfigurations and attack paths.
- **Future Security** — Security Twin-based adversarial simulation of proposed code, API, IaC, IAM, cloud and configuration changes before production.

See `docs/product-architecture.md` and `docs/security-twin.md`.

## Current phase: M1 — platform skeleton

Current real-target activation remains disabled. The repository already has
lab-only network-capable workers, but real-target adapters are a later phase
and require an explicit project-level activation decision plus valid
authorization.

The platform can already:

- define and validate target scope;
- model authorization, clients, engagements and risk approvals;
- build typed AI assessment plans from a capability registry;
- execute HTTP-header, service-inventory and TLS baselines against lab targets;
- normalize findings, evidence, remediation and retest state;
- run provider-neutral AI review/orchestration;
- expose a multi-client authenticated web shell;
- exercise planted-weakness lab scenarios and score results;
- prove fail-closed behavior with tests.

It cannot yet actively assess arbitrary real targets or execute exploit logic.

## Safety invariants

1. Unknown public targets fail closed.
2. Public targets require exact host or CIDR authorization.
3. Private/loopback lab targets can be permitted by policy.
4. Authorization has an owner/reference and optional validity window.
5. Every future active adapter must pass through the same scope gate.
6. No adapter may silently widen target scope.
7. Findings must include evidence, remediation, and retest state.
8. Parallel workers claim non-overlapping capabilities/write scopes before changes.
9. Future-state simulation never grants authorization to interact with a real target.
10. AI/model output is not itself ground truth; important findings require evidence/verifier semantics.

## Architecture

```text
                    Current state
                         |
AuthorizedTarget -> Scope/Policy -> AI Orchestrator -> Capability Workers
                         |                                |
                         v                                v
                    Security Twin <- Evidence <- Findings/Attack Paths
                         |
                  Proposed future change
                         |
                  Future-state Twin
                         |
                 Isolated simulation
                         |
             Current vs Future attack graph
                         |
                Verdict + Fix + Retest
```

## Quick start

```bash
cd lightup
python -m unittest discover -s tests -v
PYTHONPATH=src python -m lightup.cli scope-check 127.0.0.1
PYTHONPATH=src python -m lightup.cli plan 127.0.0.1
PYTHONPATH=src python -m lightup.cli create-operator --db lightup.db \
  --email you@example.com --name "You"
PYTHONPATH=src python -m lightup.cli serve --db lightup.db

# End-to-end lab demo
python lab/http_fixture.py &
PYTHONPATH=src python -m lightup.cli lab-baseline --expect-fixture

# Planner-driven multi-lane assessment against planted ground truth
python lab/vuln_fixture.py --profile exposed --port 18081 &
PYTHONPATH=src python -m lightup.cli lab-assess http://127.0.0.1:18081/ \
  --profile exposed
PYTHONPATH=src python -m lightup.cli lab-evaluations --db lightup-lab.db --limit 20
PYTHONPATH=src python -m lightup.lab_tls_score --db /tmp/lightup-tls-score.db
PYTHONPATH=src python -m lightup.lab_web_score --db /tmp/lightup-web-score.db
```

The TLS scorer evaluates the real worker against an ephemeral self-signed loopback fixture. See docs/lab-tls-scoring.md for the ground-truth contract and safety limits.

The HTTP baseline scorer compares an intentionally weak response with a hardened loopback control and persists a ground-truth-bound labeval record. See docs/lab-web-baseline-scoring.md for its scoring and safety contract.

The `plan` command is intentionally non-invasive: it only emits a structured plan.

The web shell (`docs/webapp.md`) serves the operator dashboard on `/` and the
client portal on `/portal/<client_id>`, behind session authentication with
CSRF protection.

## Platform layers

- `lightup.domain` — multi-client persistence with in-code tenant isolation.
- `lightup.ai.gateway` — provider-neutral model gateway.
- `lightup.ai.orchestration` — typed tool calls, immutable run context, policy gate and evidence ledger.
- `lightup.labeval` — lab-only evaluation run path and benchmark schema.
- `lightup.webapp` — minimal progressive-disclosure web shell.
- **Security Twin (planned)** — durable current-state model, attack graph and future-state change simulation.

See `docs/ai-orchestration.md` for the AI-layer contracts.


## Combined lab score suite

Run the service-inventory, TLS-baseline and HTTP-baseline loopback scorers together, with independent evidence databases and a private aggregate report:

```bash
PYTHONPATH=src python -m lightup.lab_score_suite --output-dir ./lab-score-run-001
# Later: verify saved local evidence without rerunning any scorer
PYTHONPATH=src python -m lightup.lab_score_inspect --output-dir ./lab-score-run-001
```

The output directory must be new; saved runs can later be verified read-only with `lightup-lab-score-inspect` (installed entry point). See [the suite contract](docs/lab-score-suite.md) for its metrics, persisted-evidence checks, storage permissions and loopback-only safety boundary. Verification is lab-local storage integrity, not real-target permission or deployment approval.

Compare two independently saved loopback lab score runs offline with `lightup-lab-score-compare --baseline-dir RUN_A --candidate-dir RUN_B` (see [operator guide](docs/lab-score-suite.md)); comparison does not execute an assessment or grant authority.
For a private-safe human-readable review, add `--format text` (JSON remains the default).
For automatic two-run localhost calibration plus saved evidence verification, use `lightup-lab-score-calibrate --output-dir NEW_PRIVATE_DIR` (text by default, `--format json` optional); this never authorizes external assessment. Revisit both saved runs without rerunning fixtures with `--verify-output-dir EXISTING_PRIVATE_DIR`. Compare two complete saved calibrations without rerunning scorers with `--compare-calibrations PREVIOUS_PRIVATE_DIR CURRENT_PRIVATE_DIR`.
For offline human triage of 2–8 original private calibrations, run `lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 [ARCHIVE3 ...] --format html --html-output-dir NEW_PRIVATE_REVIEW_DIR`. The saved 0700/0600 offline report shows a keyboard-scrollable PASS/HOLD pair matrix, an anonymous archive review queue ordered by the number of affected pairs (including per-archive evidence reuse and score drift counts), and an allowlisted per-capability hotspot table linking to the original affected pairs. The saved report includes a new 0600 `review_summary.json` with canonical index-only pair statuses, anonymized archive priorities and allowlisted metric hotspots for local scripts, bound to the original private receipts alongside `history.html`. Neither report contains source files, source paths, evidence digests, identities, scripts or network resources. For a human-readable handoff with no saved output, `--compare-history ARCHIVE1 ARCHIVE2 ... --format review-markdown` prints a source-free prioritized Markdown brief (HOLD/replay/drift by anonymous archive, fixed scorer hotspots, every pair). Genuine HOLD exits 2 with the brief; corrupt original evidence emits a path-free stderr refusal and no partial stdout. For a previously saved private three-file report, add
`--verify-html-output-dir EXISTING_PRIVATE_REVIEW_DIR` with either
 `--format review-json`, `--format review-markdown` or `--format review-csv`. All exports first
verify the original source bindings, saved HTML, JSON and receipt; tampered
reports produce no substitute output. This never grants test or release
authorization. For stdout-only automation without creating a review directory, use `--compare-history ARCHIVE1 ARCHIVE2 ... --format review-json`; it prints the exact same anonymous, validated `review_summary.json` schema and emits a safe HOLD on invalid original evidence. Verify the private report read-only with the *same original archives* using `--verify-html-output-dir EXISTING_PRIVATE_REVIEW_DIR` instead of `--html-output-dir`; this is synthetic localhost evidence review, not target or release authorization.

The portable receiver also checks both HTML documents for a strict, local-only
content policy, inert HTML elements/attributes, and bounded offline navigation.
Even a canonical ZIP with recomputed unsigned SHA-256 manifest digests is
refused if it includes scripts, redirects, event handlers, external resources
or active CSS. Existing inert legacy HTML handoffs remain supported. This is
content safety, **not** original-source authentication or consent.

The source-free portable ZIP now opens with an **accessible, scriptless offline
operator dashboard** (`index.html`). It shows anonymous original archive and
pair totals, global PASS/HOLD, prioritized evidence-reuse/score-drift cases,
all original pair flags with deep links into the verified local `history.html`
review, first-party scorer hotspots, and the Markdown/CSV/JSON handoffs.
There are no remote assets, JavaScript, original source paths, receipt hashes,
target identities or implied authorization. The dashboard is a display of
already-verified *synthetic* localhost comparison flags; neither a green
status nor a human clicking a link grants assessment or release rights.

For a deterministic one-command **portable offline HUMAN review ZIP** of the already
saved three-file private review, run:

```sh
lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 \
  --format html --verify-html-output-dir EXISTING_PRIVATE_REVIEW_DIR \
  --portable-review-output-dir NEW_PRIVATE_HANDOFF_DIR
```

The CLI **first** verifies the original archives and exact saved private HTML,
JSON and receipt, then produces one no-overwrite 0600 ZIP in a fresh 0700
private directory, and verifies the same source-bound report again after
publication. The ZIP contains only scriptless index and history HTML,
source-free JSON/CSV/Markdown, README and SHA-256 manifest for the exports.
No original sources, paths, receipt identities, private bindings or target
authority are included. HTML deliberately includes allowlisted numeric
first-party score changes for HUMAN review; CSV/JSON/Markdown do not contain
those raw numeric values. ZIP hashes check export integrity only, not source
authenticity. A real original-evidence reuse HOLD remains a HOLD in the ZIP
and exit status 2; a corrupt original or receipt refuses publication. There is
no live target, security scan, grant, consent, review approval or deployment.

A recipient can validate the transported ZIP in its owner-private directory,
without opening the original archive or network:

```sh
lightup-lab-score-calibrate --verify-portable-review \
  NEW_PRIVATE_HANDOFF_DIR/LightUp-SYNTHETIC-OFFLINE-REVIEW.zip
```

This read-only checker rejects duplicate/unexpected ZIP entries, unsafe
permissions and symlinks, oversized members, malformed/contradictory anonymous
pair or manifest metadata, changed export digests, and *non-canonical ZIP
bytes* (including otherwise ignored prepended/appended material). It returns
TRANSPORT VERIFIED plus the original review PASS/HOLD state, never private source paths.
It cannot authenticate the original source or its signer: a forged ZIP with
recomputed unsigned hashes is not trusted original evidence or an approval.
Keep the ZIP in a 0700 directory as a 0600 file for this local checker.

To open a verified portable HUMAN ZIP as scriptless files without manual ZIP
extraction, use the same first-party CLI in an owner-private working area:

```sh
lightup-lab-score-calibrate --unpack-portable-review \
  PRIVATE_DIR/LightUp-SYNTHETIC-OFFLINE-REVIEW.zip \
  --unpack-output-dir NEW_PRIVATE_BROWSE_DIR
```

This offline operation validates the *entire* canonical ZIP byte stream,
manifest, bounded members and anonymous status from a single immutable read
before publishing anything. It creates a new 0700 directory containing exactly
seven fixed-name 0600 source-free files, including `index.html` for local
browser review, and refuses overwrite, symlinks, unknown entries, appended ZIP
bytes and source/output overlap. To re-open the same offline review later, revalidate all seven existing
files read-only against the canonical source-free ZIP (no rescoring):

```sh
lightup-lab-score-calibrate --verify-unpacked-review \
  PRIVATE_DIR/LightUp-SYNTHETIC-OFFLINE-REVIEW.zip \
  --unpacked-review-dir EXISTING_PRIVATE_BROWSE_DIR
```

Reinspection rejects modified, added, missing or symlinked files and a changed
ZIP; PASS/HOLD is preserved. This is transport comparison only and does not
authenticate original evidence or authorize assessments.

A genuine evidence-reuse HOLD still publishes
an inspectable HOLD review with exit 2, never a PASS. Corrupt inputs produce no
files. No original source identity, external target permission or human review
approval is gained from verification or unpacking.

For privacy-minimal spreadsheet handoff use `--compare-history ARCHIVE1 ARCHIVE2 --format review-csv`: only archive ordinals, PASS/HOLD and two boolean evidence/score flags. Add `--verify-html-output-dir` to bind it to the already saved private three-file review; unlike regular `--format csv`, this never exports original score values.


For many archives, add `--focus-archive-index N` to the source-free
`--format review-json`, `--format review-csv` or `--format review-markdown`
handoff. This prioritizes comparisons involving the selected 1-based archive
but never narrows original source verification or the global HOLD status.
Focused CSV rows explicitly retain the full-history status and HOLD count.


Offline browser reviewers can also run
`--compare-history ARCHIVE1 ARCHIVE2 --format html --focus-archive-index 1`
for a static, keyboard-accessible per-archive comparison table plus the full
global matrix and unchanged overall HOLD status. Add
`--verify-html-output-dir EXISTING_PRIVATE_REVIEW_DIR` to verify the saved
canonical private review before emitting focused HTML; focused HTML cannot
replace the saved canonical report.


The canonical saved offline `history.html` now has built-in keyboard-accessible
per-archive navigation for all 2–8 verified original archives: native
`details` panels show pairwise evidence independence, stability, PASS/HOLD,
and local HOLD links without scripts or network. Focused one-archive exports
are still available separately and the global review verdict is unchanged.


The offline review priorities and first-party scorer hotspots link to *all*
affected original HOLD comparisons in the same private static HTML page, so
multi-archive regressions can be triaged without rerunning CLI exports.
