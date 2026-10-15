# LightUp — GitHub REST-export veilig beoordelen zonder werk toe te wijzen

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** De nieuwe import in [`scripts/scope_issue_github_rest_import_20261015.py`](../scripts/scope_issue_github_rest_import_20261015.py) maakt de eerder uitsluitend handmatig samengestelde scope-workerconflictcontrole bruikbaar met dezelfde recordvormen als de GitHub REST API. De import zelf voert **geen** netwerkverzoek, scan, echte autorisatie, branchwijziging, merge of deployment uit.

## Waarom deze stap?

De eerdere offline audit verwachtte al aangepaste JSON-velden voor PR’s en bestandsnamen. Daardoor was handmatig werk nodig om GitHub-resultaten om te zetten, met risico op ontbrekende PR's, forkverwarring en het weglaten van `previous_filename` bij hernoemingen. Deze adapter leest de relevante **native GitHub-recordvelden**, herkent onvolledige pagina's en gebruikt alleen een *afzonderlijke*, expliciete opgave van de Notion-scope-issues en PR-claims. Zij probeert **nooit** op basis van een issuevermelding in PR-titel of -beschrijving automatisch toestemming/eigenaarschap te raden.

## Verplicht lokaal pakket

Het invoerbestand is één JSON-object met exact de velden `repository`, `issue_pages`, `pr_pages`, `file_pages`, `scope_issue_numbers`, `claims`. Een klein, volledig synthetisch voorbeeld:

```json
{
  "repository": "Zennay/Lightup",
  "scope_issue_numbers": [101],
  "issue_pages": [
    {"page": 1, "has_next": false, "records": [
      {"number": 101, "state": "open", "title": "synthetic"}
    ]}
  ],
  "pr_pages": [
    {"page": 1, "has_next": false, "records": [
      {"number": 201, "state": "open", "draft": true,
       "base": {"ref": "main", "sha": "3333333333333333333333333333333333333333",
                "repo": {"full_name": "Zennay/Lightup"}},
       "head": {"sha": "1111111111111111111111111111111111111111",
                "repo": {"full_name": "Zennay/Lightup"}}}
    ]}
  ],
  "claims": [
    {"pr": 201, "issues": [101]}
  ],
  "file_pages": [
    {"pr": 201, "page": 1, "has_next": false, "records": [
      {"filename": "tests/example.py", "status": "added"}
    ]}
  ]
}
```

```sh
python scripts/scope_issue_github_rest_import_20261015.py < github-local-export.json
python -m unittest discover -s tests -p 'test_scope_issue_github_rest_import_20261015.py' -v
```

De twee relevante API-recordtypen zijn GitHub **issue** (`number`, `state`; geen `pull_request`-row) en **pull request** (`number`, `state`, `draft`, `base.ref`, `base.sha`, `base.repo.full_name`, `head.sha`, `head.repo.full_name`), plus het **PR-file-record** (`filename`, `status`, bij `renamed` verplicht `previous_filename`). Alleen een pagina-wrapper met `page`, `has_next` en `records` is lokaal toegevoegd om volledigheid zichtbaar te maken. GitHub-issues en PR's moeten apart zijn verzameld; GitHub's algemene issues-API kan ook PR's teruggeven, maar die mogen hier niet als werkissues worden gezien. De aanleveraar moet scope-lane en claims onafhankelijk tegen actuele Notion en bronhouders controleren.

## Veiligheidscontract en beperkingen

- De import valideert opeenvolgende pagina's, unieke nummers, geldige paden, hernoemingen, GitHub-baserepository `Zennay/Lightup`, branch `main`, SHA-vormen, forks en expliciet geclaimde issues; conflicten worden als **waargenomen, niet als volledig bewezen** gegroepeerd.
- Open PR's zonder files of zonder expliciete claimmelding en onvolledige issue-/PR-/bestandspaginering maken `snapshot_complete_self_asserted: false`. Ook bij een volledig zelf verklaarde export staan `source_provenance_verified: false`, `worker_activity_verified: false` en `head_pinning_verified: false`.
- Geen enkele uitvoer bevat een lijst met vermeend vrije issues: `candidate_list_suppressed: true` en `unclaimed_candidates_not_permission: []` blijven vast.
- Alle vijf autorisatie-, scan-, merge-, deploy- en releasevlaggen zijn letterlijk **false**. Zowel geldige als ongeldige input geeft `status: HOLD` en exitcode **2**, met privacy-minimale foutmelding.
- De import is een **zelf opgegeven offline extractie, geen geauthenticeerde GitHub-attestatie**. Hij controleert geen live PR-headversie vóór en na het ophalen; de [headconsistentie-audit](scope-issue-pr-head-consistency-20261015.md) en [repository-identity-audit](scope-issue-repo-identity-20261015.md) zijn aparte controles. De afwezigheid van waargenomen conflicten zegt niets over beschikbaarheid van werk.

Het onderdeel dient uitsluitend ter voorbereiding van een menselijke review. Geen productiemacht en geen formele security/privacy- of VPS-CI-goedkeuring.
## Direct uitvoerbaar voorbeeld zonder klantgegevens

Er staat nu een volledig inert, **SYNTHETIC** voorbeeld in [`lab/scope_github_rest_export_synthetic_20261015.json`](../lab/scope_github_rest_export_synthetic_20261015.json). Het bevat twee fictieve PR's, één hernoeming en een botsing op het **oude** pad, maar geen echte targets, tokens of autorisaties. Draai de import én het menselijke rapport rechtstreeks vanuit de repository-root:

```sh
python scripts/scope_issue_github_rest_import_20261015.py < lab/scope_github_rest_export_synthetic_20261015.json
python scripts/scope_issue_github_rest_report_20261015.py < lab/scope_github_rest_export_synthetic_20261015.json
python -m unittest discover -s tests -p 'test_scope_issue_github_rest_smoke_20261015.py' -v
```

**Let op:** beide CLI's geven ook op correcte input bewust exitstatus **2/HOLD**, geen normale success-exitstatus 0. Als een shellcommando automatisch stopt bij exit 2, is dat hier de verwachte veiligheidsuitkomst. De volledig synthetische PR- en issue-nummers zijn geen verwijzing naar echte GitHub-items.
