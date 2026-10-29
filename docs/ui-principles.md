# UI principles

LightUp should feel calm even when the underlying assessment is complex.

## Rules

1. **One primary action per screen.**
2. Show outcomes first; implementation details live behind progressive disclosure.
3. Prefer short status summaries over dense security dashboards.
4. Do not expose raw agent/tool noise by default.
5. High-risk actions must become visually explicit only when selected.
6. Authorization, scope and risk must be understandable before an operator approves execution.
7. Client-facing screens prioritize impact, fix and retest status over scanner terminology.

## Admin navigation

Keep the permanent navigation small:

- Overview
- Discovery
- Clients
- Assessments

Settings and advanced controls can live behind a secondary menu.

## Prospect card

Default:

```text
Company
Potential exposure: High
Confidence: 82%
Active testing: Locked

[View signals] [Contact] [Request authorization]
```

Technical evidence and source details appear only after expansion.

## Assessment view

Default:

```text
Client / Engagement
Status
Scope summary
Risk level
Authorization status

Findings
- Critical 1
- High 2
- Medium 3

[Review findings]
```

Tool traces, capability lanes, model decisions and raw evidence are hidden under Advanced details.

## Risk control

The risk selector must display plain-language impact. Selecting a higher level shows only the additional implications and approvals needed for that level.

The UI must never be able to bypass backend policy.

## Client portal: first-screen contract

- Keep the persisted-state next action first. It must say who acts next and link to the real request, scope plan or private evidence page; it is navigation, never authorization.
- Keep the four task shortcuts visible: requests, scope and safety, recorded findings, and the private report.
- **Simplify:** place secondary assessment counts, recent request cards and per-engagement coverage detail in native, initially closed `<details>` disclosures. Keep their underlying records and links intact so the first screen does not become a stack of duplicate KPI cards.
- **Keep:** the concise coverage summary, unknown/partial/not-authorized warnings, first findings needing HUMAN follow-up, current scope blockers and the explicit “testing locked” state visible. A collapsed detail view must never hide the primary safety boundary.
- **Merge:** keep a single path to the full request inbox; the home-screen recent-request disclosure is a short preview, not a second full inbox.
- Use text labels and native keyboard-operable disclosures, retain visible focus and 44px touch targets, and keep the same state/tenant checks. Do not use color, zero findings or a recorded fix as proof of safety.
- The CSV export link is attached to the current anchored “Recorded findings” heading, so renaming UI copy cannot silently remove an existing user action.
