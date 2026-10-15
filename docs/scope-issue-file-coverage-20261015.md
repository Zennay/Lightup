# LightUp — offline volledigheidscontrole voor PR-bestanden

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Deze onafhankelijke controle beschermt de werkverdeling van parallelle scope-authorization-workers; geen enkele uitkomst geeft toestemming om bestaand werk over te nemen.

## Geverifieerd probleem

Een deels geëxporteerd GitHub-PR-bestandenoverzicht kan een werkelijk gedeeld bestand missen, waardoor een offline audit ten onrechte "geen bestandsconflict" lijkt te tonen. De bestaande [issue-/PR-paginacontrole](scope-issue-snapshot-coverage-20261015.md) dekte niet de afzonderlijke bestandenpaginering **per PR**.

## Implementatie

De nieuwe [offline PR-file-paging-audit](../scripts/scope_issue_file_coverage_20261015.py) bouwt voort op de reeds geïsoleerde issue-/PR-controle en verwacht het volgende JSON-formaat op stdin:

```json
{
  "snapshot": {
    "issues": [{"number": 101, "open": true, "lane": "scope-authorization"}],
    "prs": [{"number": 201, "open": true, "draft": true,
             "issues": [101], "paths": ["tests/one.py"]}]
  },
  "pagination": {
    "issues": [{"page": 1, "numbers": [101], "has_next": false}],
    "prs": [{"page": 1, "numbers": [201], "has_next": false}]
  },
  "pr_file_pages": [
    {"pr": 201, "pages": [{"page": 1, "paths": ["tests/one.py"], "has_next": false}]}
  ]
}
```

```sh
python scripts/scope_issue_file_coverage_20261015.py < receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_file_coverage_20261015.py' -v
```

Voor iedere open PR is exact één set bestandenpagina's vereist. Paginanummers moeten bij 1 starten en zonder gaten oplopen; iedere tussenpagina meldt `has_next: true`. De daadwerkelijk aanwezige paden moeten exact overeenkomen met de bekende PR-snapshot. Niet-vermelde, dubbele, onbekende of mismatched paden, misleidende Unicode-paden, extra records of foutieve marker-typen veroorzaken generieke HOLD. Een laatste pagina met `has_next: true` betekent expliciet `INCOMPLETE_MORE_FILE_PAGES`. Een PR zonder bestandenexports krijgt `MISSING_PR_FILE_EVIDENCE`.

**Belangrijke veiligheidsgrens:** ontbrekende issues-, PR- of bestandenpagina's onderdrukken alle "unclaimed candidate"-hints. Waargenomen conflicten mogen als reviewhint blijven staan, maar de afwezigheid van conflicten betekent nooit dat een PR-pad of taak vrij is. Zelfs wanneer de volledige lokale dataset intern consistent is, blijven `source_provenance_verified`, `worker_activity_verified` en alle vijf autorisatie-/releasevlaggen letterlijk **false**. Exitcode blijft **2/HOLD**.

## Wat dit niet bewijst

De snapshot kan door de caller zijn gemanipuleerd. Dit proces authenticeert geen GitHub-antwoord, controleert geen werkersreservering, haalt zelf niets op van internet en kan niet bewijzen dat andere branches ontbreken. Het is **geen** CI-/VPS-/security-/privacybewijs, geen productie-autorisatie en geen toestemming om te mergen, deployen of echte targets te scannen. Voor echte overdracht: live GitHub/Notion, eigenaren, scope en onafhankelijke human GO verifiëren.
