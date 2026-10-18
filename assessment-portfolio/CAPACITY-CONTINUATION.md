# Explicit private human capacity continuation between original review cycles

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

The `review_cycle.py` command now optionally carries **hypothetical neutral-role capacity assumptions** from a previous ORIGINAL source-bound human plan into a NEW private human review cycle, **only after independent explicit human reconfirmation**. Old assumptions are never silently applied to a changed original agenda or promoted to a real work assignment.

The original `interactive-capacity-studio.html` already exports `lightup.assessment_portfolio_capacity_plan.v1` private JSON with bounded weekly role assumptions (0–100 human planning slots per role, 1–12 weeks). The original `capacity_plan.admitted_plan` will refuse that old plan against a changed agenda because its exact original reference date/source SHA hashes no longer match. This is deliberate.

To carry it into the **new** source, provide the old plan when starting the source-bound original human review cycle, and explicitly acknowledge the changed human context:

```sh
python3 assessment-portfolio/review_cycle.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-choices /private/ORIGINAL-choices-A.json \
  --proposal-bundle /private/ALL-original-human-proposals.json \
  --next-as-of 2026-10-19 \
  --previous-private-capacity-plan /private/OLD-source-bound-capacity.json \
  --reconfirm-human-capacity \
  --output /private/NEW-human-review-cycle.zip
```

When supplied, the previous plan **must** exactly match every previous ORIGINAL private agenda, source status and selected original reference date. Original source, original choices and original proposals must independently pass all existing strict human review cycle admission. The new exact original source membership, source-kind and HOLD status must remain unchanged. Only then are the explicitly reconfirmed numerical neutral-role/week assumptions rebound to the NEW exact agenda hashes and explicit reference date; all authorization flags remain false.

The private next-cycle ZIP gains five new offline files:
- `new-private-human-capacity-plan.json` — NEW complete original-schema human Capacity Studio plan, matched to the NEW source agenda bytes and date; import this privately into **next-human-workspace.zip** → `interactive-capacity-studio.html` via its existing Restore PRIVATE source-bound plan control.
- `new-private-human-capacity-outlook.html` — original source-neutral, private hypothetical human role/week schedule.
- `new-aggregate-human-capacity.html` and `.csv` — aggregate-only role counts and hypothetical slot pressure (small-cohort privacy review still necessary).
- `HUMAN-CAPACITY-RECONFIRMATION.txt` — states the actual source drift, human responsibility and no-action boundary.

If no old plan is provided, the new cycle behaves exactly as before and adds none of these optional artifacts. Supplying a plan **without** `--reconfirm-human-capacity`, or reconfirming with no plan, fails closed with HOLD before any new output. Any changed/invalid old source, original source count, capacity value, role, week, date, status or missing required original also HOLDs the whole transaction. The previous plan, previous and next original manifests, choices, proposed source documents and prior ZIP are never modified; `publish()` only atomically creates a new 0600 ZIP without overwrite.

This is a planning-only numerical handoff, not an employee assignment, SLA, remediation/retest, verified finding, scanner, client consent, grant, engagement execution or authorization. A source hash is an unsigned local byte correlation. Even after explicit human reacknowledgment, role capacities may no longer be appropriate if neutral role needs change — review the next plan yourself. Mandatory original exact-head hosted/permanent named VPS CI, source-owner and independent privacy/security acceptance, genuinely independently authenticated client and operator permission with action-time revocation, #177/#182/#829, and explicit HUMAN GO remain unchanged for release.
