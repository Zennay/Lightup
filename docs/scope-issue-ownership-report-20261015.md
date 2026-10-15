# LightUp: leesbaar offline scope-ownershipoverzicht (2026-10-15)

**Status: INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.**

De overzichts-CLI is een toevoeging aan de strikte snapshot-audit in `scripts/scope_issue_ownership_audit_20261015.py`. Er wordt geen live GitHub, Notion, netwerk, doelwit of account benaderd. Het rapport gebruikt alleen de door de operator expliciet aangeleverde JSON-snapshot.

## Gebruik

```sh
python scripts/scope_issue_ownership_report_20261015.py < snapshot.json
python -m unittest discover -s tests -p 'test_scope_issue_ownership*.py' -v
```

Het rapport is in begrijpelijk Nederlands en laat zien:
- Open issues waarvoor in deze **beperkte momentopname** geen PR-claim bekend is.
- Open issues die meerdere PR's claimen, inclusief nummers.
- Exacte overlappende gewijzigde bestandspaden van open PR's.
- Gesloten of onbekende issues die alsnog als claim in een open PR voorkomen.
- Concept-PR's waarvoor geen groen of autorisatie wordt aangenomen.

Het rapport is geen gezaghebbende lijst met vrije taken: een snapshot kan onvolledig, verouderd of gemanipuleerd zijn. Bij fouten verschijnt alleen een generieke HOLD-melding zonder inhoud uit afgewezen input. Het formaat escape't bestandsnamen om HTML/Markdown-injectie te beperken. **De exitcode is altijd 2, ook als alle controles inhoudelijk goed lijken.**

Niets van dit hulpmiddel is bewijs voor operatorconsent, risico-5 vrijgave, runtime-scope, werkelijke runner-testen of release. Voor iedere daadwerkelijke overdracht blijven actuele branch- en PR-controle en menselijke beoordeling verplicht. Geen merge/deploy/scans/real grants.
