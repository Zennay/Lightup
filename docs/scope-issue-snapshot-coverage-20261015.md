# LightUp scope-authorization — paginering en onbekende werkverdeling

**Fase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Deze afzonderlijke offline controle is ontworpen om schijnzekerheid uit onvolledige GitHub-exports weg te nemen. Zij is geen vervanging voor actuele GitHub/Notion-controle of toestemming.

## Waarom

Een simpele export met de eerste 100 open PR's kan een issue ten onrechte als niet geclaimd tonen wanneer een relevante PR op pagina twee staat. Het bestaande `scope_issue_ownership_audit_20261015.py` werkt uitsluitend met de aangeleverde selectie. De aanvullende [paginacontrole](../scripts/scope_issue_snapshot_coverage_20261015.py) vergelijkt aantallen, unieke identiteiten, opeenvolgende paginanummers en `has_next`-markeringen. Als een pagina nog niet is geëxporteerd, wordt de kandidaatlijst **helemaal onderdrukt**.

## Invoer

Gebruik de bestaande [snapshotstructuur](scope-issue-ownership-audit-20261015.md) ingepakt met een paginareceipt:

```json
{
  "snapshot": {
    "issues": [{"number": 12, "open": true, "lane": "scope-authorization"}],
    "prs": [{"number": 20, "open": true, "draft": true, "issues": [12], "paths": ["tests/a.py"]}]
  },
  "pagination": {
    "issues": [{"page": 1, "numbers": [12], "has_next": false}],
    "prs": [{"page": 1, "numbers": [20], "has_next": false}]
  }
}
```

```sh
python scripts/scope_issue_snapshot_coverage_20261015.py < receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_snapshot_coverage_20261015.py' -v
```

Alleen de consistente vorm krijgt `SELF_ASSERTED_COMPLETE_UNVERIFIED`: **zelf opgegeven volledigheid is géén geauthenticeerd GitHub-bewijs**. Een laatste `has_next: true` betekent `INCOMPLETE_MORE_PAGES` en zet `candidate_list_suppressed: true`. Gegevens die niet met de pagingstructuur overeenkomen, verkeerde typen, niet-opeenvolgende pagina's, ontbrekende pagina's en dubbele identifiers worden afgewezen. Ook als alle pagina's intern lijken te kloppen, blijven `source_provenance_verified`, `worker_activity_verified` en alle vijf autorisatie- en releasevlaggen **false**, status **HOLD**, exitcode **2**. Conflictgroepen van reeds waargenomen PR's blijven ter review beschikbaar.

## Grenzen

Geen live connector, externe URL, scanner, credential, toestemming, uitvoerder, auto-claim, merge of deploy. Een gemanipuleerde bron kan volledigheid veinzen; deze test bewijst uitsluitend *interne* consistentie van een offline export en kan nooit bepalen of een issue echt vrij is. Verifieer bij daadwerkelijke werktoewijzing altijd live GitHub, Notion, branch-head en mogelijke andere workers. Permanente geregistreerde VPS-CI, productiebronhouders, privacy/security review en expliciete menselijke GO blijven releasevoorwaarden.
