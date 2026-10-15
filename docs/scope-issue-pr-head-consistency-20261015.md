# LightUp · offline PR-head-verschillen tussen snapshotpagina's (DRAFT/HOLD)

**Fase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Deze onafhankelijke tool verandert niets aan oorspronkelijke LightUp-runtime, bevoegdheden, CI-configuratie, workers of echte doelwitten.

## Probleem

PR #1456 controleert al issues, pull requests, bestands- en wijzigingspagina's en hernoemde paden. Een PR kan echter tussen die pagina-opvragingen nieuwe commits krijgen. Daarmee kunnen de aangeleverde bestandslijsten uit *verschillende versies* van dezelfde PR komen. Een syntactisch volledig exportbestand kan dan nog steeds conflicten missen. Dit hulpmiddel geeft zo'n export expliciet **HOLD** en onderdrukt de daaruit afgeleide conflictgroepdetails.

## Invoer en gebruik

`scripts/scope_issue_pr_head_consistency_20261015.py` accepteert hetzelfde offline rootdocument als de [rename-analyse](scope-issue-rename-footprints-20261015.md), plus exact één `pr_head_receipts`-record per open PR:

```json
"pr_head_receipts": [
  {
    "pr": 201,
    "start_head": "1111111111111111111111111111111111111111",
    "file_page_heads": ["1111111111111111111111111111111111111111"],
    "change_page_heads": ["1111111111111111111111111111111111111111"],
    "end_head": "1111111111111111111111111111111111111111"
  }
]
```

Het voorbeeld toont alleen het extra veld, **niet** een volledig geldig rootdocument. Het aantal SHA's moet overeenkomen met de daadwerkelijk aangeleverde bestands- en wijzigingspagina's van dezelfde PR. SHA-velden eisen canonieke lowercase hex van 40 of 64 tekens. Er mag geen dubbele PR voorkomen; ontbrekende paginaobservaties, andere SHA's bij start, file page, change page of eind geven `UNSTABLE_OR_INCOMPLETE`. Ook een intern constante lijst is hooguit `SELF_ASSERTED_STABLE_UNVERIFIED`, nooit echte GitHub-authenticiteit.

```sh
python scripts/scope_issue_pr_head_consistency_20261015.py < offline-pr-receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_pr_head_consistency_20261015.py' -v
```

## Resultaat en grenzen

Bij mogelijke versie-drift of incompleet bewijs blijven `observed_conflict_groups: []` en `conflicts_suppressed_for_mixed_heads: true`. Daarmee wordt er **geen** mogelijk onbetrouwbare werktoewijzing voorgesteld. De tool geeft altijd `status: HOLD`, exitcode **2**, alle toestemming-/scan-/merge-/deploy-/releasevlaggen letterlijk **false** en geen werkverdelingsmacht. Ook bij syntactisch volledige, uniforme SHA's blijven `source_provenance_verified` en `worker_activity_verified` false en `unclaimed_candidates_not_permission` leeg.

**Dit is een consistency check, geen bronverificatie**: een kwaadwillende of verouderde export kan overal dezelfde foutieve SHA claimen. De gebruiker moet actuele bronversies, paginering en eigenaarschap onafhankelijk controleren op GitHub en Notion. Geen automatische fetch/lock, actieve scan, operatorgrant, merge of deployment; VPS-CI, security/privacy review en menselijk GO blijven afzonderlijke blockers.