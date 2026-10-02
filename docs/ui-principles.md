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
